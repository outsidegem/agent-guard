import { randomUUID } from 'node:crypto';
import {
  calculateFeeSplit,
  resolveFeeRecipient,
  verifyCapability,
  type FeeSplitResult
} from '@digital-mineral/agent-escrow';
import {
  BaseL2PaymentSettlement,
  HardenedPaymentVerifier,
  PaymentState,
  SettlementMode,
  type BaseL2SettlementConfig,
  type PaymentSettlement
} from '@digital-mineral/agent-pay-handshake';
import { BurnBouncer, type BouncerConfig, type BurnReservation } from '@digital-mineral/burn-bouncer';
import {
  AuditLogger,
  EnvironmentCredentialProvider,
  McpGateway,
  NetworkValidator,
  PolicyEngine,
  RateLimiter,
  Role,
  SecureHttpExecutor,
  type CredentialProvider,
  type ExternalAuthorizationProvider,
  type LegacyToolDefinition
} from '@digital-mineral/mcp-bridge';
import {
  NodeIdentity,
  NodeRegistry,
  ReceiptSigner,
  ReceiptVerifier,
  SqliteReceiptStore,
  SystemTelemetryProvider,
  type ComputeReceipt,
  type ReceiptStore,
  type TelemetryProvider
} from '@digital-mineral/telemetry-witness';
import { AgentGuardError, AgentGuardErrorCode } from './errors.js';
import {
  LemonSqueezyLicenseValidator,
  maskLicenseKey,
  type LicenseValidatorConfig
} from './license.js';
import type {
  GuardAuditStage,
  GuardExecutionOutcome,
  GuardExecutionRequest,
  ValidatedEntitlement
} from './types.js';

export interface AgentGuardConfig {
  /** Lemon Squeezy license validation configuration. */
  license?: LicenseValidatorConfig;
  /** Pre-configured LemonSqueezyLicenseValidator instance. */
  licenseValidator?: LemonSqueezyLicenseValidator;
  /** BurnBouncer configuration (rolling OPEX circuit breaker). */
  bouncer?: BouncerConfig;
  /** Pre-configured BurnBouncer instance. */
  bouncerInstance?: BurnBouncer;
  /** SQLite storage path for `SqliteReceiptStore` (`:memory:` by default). */
  witnessDbPath?: string;
  /** Custom ReceiptStore implementation. */
  receiptStore?: ReceiptStore;
  /** Custom NodeIdentity for signing local compute receipts. */
  nodeIdentity?: NodeIdentity;
  /** Custom NodeRegistry for verifying compute receipts. */
  nodeRegistry?: NodeRegistry;
  /** Custom TelemetryProvider for compute receipt metrics. */
  telemetryProvider?: TelemetryProvider;
  /** Custom CredentialProvider for MCP tool execution. */
  credentialProvider?: CredentialProvider;
  /** Custom SecureHttpExecutor for MCP tool execution. */
  httpExecutor?: SecureHttpExecutor;
  /** Optional human/escrow approval provider for state-mutating POST/PUT/DELETE tools. */
  escrowApprovalProvider?: ExternalAuthorizationProvider;
  /** Rate limit max requests per window per agent+tool. Default 100. */
  rateLimitMaxRequests?: number;
  /** Rate limit window in ms. Default 60000. */
  rateLimitWindowMs?: number;
  /** Base L2 settlement configuration or custom `PaymentSettlement` instance. */
  settlement?: BaseL2SettlementConfig | PaymentSettlement;
  /** Protocol fee recipient EVM address on Base L2. */
  feeRecipientHex?: string;
  /** Require x402 payment input on every execution request. Default false. */
  requirePayment?: boolean;
}

function redactSensitiveText(input: string, rawLicenseKey?: string): string {
  let sanitized = input
    .replace(/(bearer\s+)[^\s,;]+/gi, '$1[REDACTED]')
    .replace(/(api_key=)[^\s&]+/gi, '$1[REDACTED]')
    .replace(/(license_key=)[^\s&]+/gi, '$1[REDACTED]');
  if (rawLicenseKey && rawLicenseKey.trim().length > 4) {
    sanitized = sanitized.split(rawLicenseKey.trim()).join(maskLicenseKey(rawLicenseKey));
  }
  return sanitized;
}

export class AgentGuard {
  public readonly licenseValidator: LemonSqueezyLicenseValidator;
  public readonly bouncer: BurnBouncer;
  public readonly gateway: McpGateway;
  public readonly auditLogger: AuditLogger;
  public readonly nodeIdentity: NodeIdentity;
  public readonly nodeRegistry: NodeRegistry;
  public readonly receiptStore: ReceiptStore;
  public readonly receiptSigner: ReceiptSigner;
  public readonly receiptVerifier: ReceiptVerifier;
  public readonly paymentVerifier: HardenedPaymentVerifier;
  public readonly settlement: PaymentSettlement;

  private readonly tools = new Map<string, LegacyToolDefinition>();
  private readonly activeAgents = new Set<string>();
  private readonly idempotencyCache = new Map<string, GuardExecutionOutcome>();
  private readonly rawLicenseKey?: string;
  private readonly feeRecipientHex?: string;
  private readonly requirePayment: boolean;
  private closed = false;

  constructor(config: AgentGuardConfig = {}) {
    this.rawLicenseKey = config.license?.licenseKey ?? process.env.LEMON_SQUEEZY_LICENSE_KEY;
    this.feeRecipientHex = config.feeRecipientHex;
    this.requirePayment = config.requirePayment ?? false;

    this.licenseValidator =
      config.licenseValidator ?? new LemonSqueezyLicenseValidator(config.license);

    this.bouncer =
      config.bouncerInstance ??
      new BurnBouncer(
        config.bouncer ?? {
          maxOpexLimit: 100,
          rollingWindowMs: 3_600_000,
          storagePath: ':memory:'
        }
      );

    this.auditLogger = new AuditLogger();
    const credentialProvider = config.credentialProvider ?? new EnvironmentCredentialProvider();
    const executor = config.httpExecutor ?? new SecureHttpExecutor(credentialProvider);
    const policyEngine = new PolicyEngine();
    const rateLimiter = new RateLimiter(
      config.rateLimitMaxRequests ?? 100,
      config.rateLimitWindowMs ?? 60_000
    );
    this.gateway = new McpGateway(
      executor,
      this.auditLogger,
      policyEngine,
      rateLimiter,
      config.escrowApprovalProvider
    );

    this.nodeIdentity = config.nodeIdentity ?? new NodeIdentity();
    this.nodeRegistry = config.nodeRegistry ?? new NodeRegistry();
    this.nodeRegistry.registerKey(this.nodeIdentity.nodeId, 'key-v1', this.nodeIdentity.publicKey);

    this.receiptStore =
      config.receiptStore ?? new SqliteReceiptStore(config.witnessDbPath ?? ':memory:');
    const initialSeq = this.receiptStore.getLastSequenceNumber
      ? this.receiptStore.getLastSequenceNumber(this.nodeIdentity.nodeId)
      : 0;
    this.receiptSigner = new ReceiptSigner(
      this.nodeIdentity,
      config.telemetryProvider ?? new SystemTelemetryProvider(),
      'key-v1',
      initialSeq
    );
    this.receiptVerifier = new ReceiptVerifier(this.nodeRegistry, this.receiptStore);

    this.paymentVerifier = new HardenedPaymentVerifier();
    if (config.settlement && 'settle' in config.settlement) {
      this.settlement = config.settlement;
    } else {
      this.settlement = new BaseL2PaymentSettlement(config.settlement);
    }
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new AgentGuardError(AgentGuardErrorCode.GUARD_CLOSED, 'AgentGuard instance is closed.');
    }
  }

  public registerTool(tool: LegacyToolDefinition, registrarRole: Role = Role.ADMIN): void {
    this.assertOpen();
    this.gateway.registerTool(tool, registrarRole);
    this.tools.set(tool.name, tool);
  }

  public getActiveAgentCount(): number {
    return this.activeAgents.size;
  }

  public calculateTierFeeSplit(
    grossAmount: bigint,
    entitlement: ValidatedEntitlement,
    overrideRecipientHex?: string
  ): FeeSplitResult {
    return calculateFeeSplit(grossAmount, {
      tier: entitlement.tier,
      feeRecipient: resolveFeeRecipient(overrideRecipientHex ?? this.feeRecipientHex)
    });
  }

  public async execute(request: GuardExecutionRequest): Promise<GuardExecutionOutcome> {
    const decisionTrail: GuardAuditStage[] = [];
    const recordStage = (
      stage: GuardAuditStage['stage'],
      status: GuardAuditStage['status'],
      detail: string
    ) => {
      decisionTrail.push({
        stage,
        status,
        timestamp: Date.now(),
        detail: redactSensitiveText(detail, this.rawLicenseKey)
      });
    };

    if (this.closed) {
      recordStage('FINALIZE', 'FAIL', 'AgentGuard instance is closed.');
      return {
        success: false,
        errorCode: AgentGuardErrorCode.GUARD_CLOSED,
        errorMessage: 'AgentGuard instance is closed.',
        decisionTrail
      };
    }

    if (
      !request ||
      typeof request.idempotencyKey !== 'string' ||
      request.idempotencyKey.trim() === '' ||
      !request.agent ||
      typeof request.agent.id !== 'string' ||
      request.agent.id.trim() === '' ||
      typeof request.toolName !== 'string' ||
      request.toolName.trim() === ''
    ) {
      recordStage('IDEMPOTENCY', 'FAIL', 'Malformed GuardExecutionRequest.');
      return {
        success: false,
        errorCode: AgentGuardErrorCode.INVALID_REQUEST,
        errorMessage: 'Invalid execution request: idempotencyKey, agent.id, and toolName are required.',
        decisionTrail
      };
    }

    // 1. Idempotency check
    const existingOutcome = this.idempotencyCache.get(request.idempotencyKey);
    if (existingOutcome) {
      const replayTrail: GuardAuditStage[] = [
        ...existingOutcome.decisionTrail,
        {
          stage: 'IDEMPOTENCY',
          status: 'REPLAYED',
          timestamp: Date.now(),
          detail: `Replayed cached outcome for idempotencyKey ${request.idempotencyKey}`
        }
      ];
      return {
        ...existingOutcome,
        replayedIdempotent: true,
        decisionTrail: replayTrail
      };
    }
    recordStage('IDEMPOTENCY', 'PASS', `Fresh idempotencyKey ${request.idempotencyKey}`);

    // 2. License validation & trusted tier resolution (ignoring any client-supplied claimedTier)
    let entitlement: ValidatedEntitlement;
    try {
      entitlement = await this.licenseValidator.validate();
      const ignoredClaimNotice = request.agent.claimedTier
        ? ` (ignored untrusted claimedTier=${request.agent.claimedTier})`
        : '';
      recordStage(
        'LICENSE',
        'PASS',
        `Resolved tier=${entitlement.tier} feeBps=${entitlement.feeBps.toString()} key=${entitlement.maskedKey}${ignoredClaimNotice}`
      );
    } catch (err: any) {
      const code =
        err instanceof AgentGuardError
          ? err.code
          : AgentGuardErrorCode.LICENSE_VERIFICATION_FAILED;
      const msg = redactSensitiveText(err?.message || 'License validation failed.', this.rawLicenseKey);
      recordStage('LICENSE', 'FAIL', msg);
      return {
        success: false,
        errorCode: code,
        errorMessage: msg,
        decisionTrail
      };
    }

    // 3. Active agent quota enforcement based on validated tier
    const agentId = request.agent.id.trim();
    if (!this.activeAgents.has(agentId) && this.activeAgents.size >= entitlement.maxActiveAgents) {
      const msg = `Active agent quota exceeded for tier ${entitlement.tier}: max ${entitlement.maxActiveAgents} active agent(s).`;
      recordStage('AGENT_QUOTA', 'FAIL', msg);
      return {
        success: false,
        errorCode: AgentGuardErrorCode.AGENT_QUOTA_EXCEEDED,
        errorMessage: msg,
        entitlement,
        decisionTrail
      };
    }
    this.activeAgents.add(agentId);
    recordStage(
      'AGENT_QUOTA',
      'PASS',
      `Agent ${agentId} authorized (${this.activeAgents.size}/${entitlement.maxActiveAgents} active)`
    );

    // 4. Optional Capability verification (AgentEscrow)
    if (request.capability) {
      const capValid =
        verifyCapability(request.capability) &&
        request.capability.agentId === agentId &&
        request.capability.resource === request.toolName;
      if (!capValid) {
        const msg = 'Capability token is invalid, expired, or does not match agent/resource.';
        recordStage('CAPABILITY', 'FAIL', msg);
        return {
          success: false,
          errorCode: AgentGuardErrorCode.INVALID_CAPABILITY,
          errorMessage: msg,
          entitlement,
          decisionTrail
        };
      }
      recordStage('CAPABILITY', 'PASS', `Verified capability ${request.capability.capabilityId}`);
    }

    // 5. Pre-flight Target SSRF Validation before reserving budget
    const registeredTool = this.tools.get(request.toolName);
    if (!registeredTool) {
      const msg = `Tool "${request.toolName}" is not registered.`;
      recordStage('TARGET_VALIDATION', 'FAIL', msg);
      return {
        success: false,
        errorCode: AgentGuardErrorCode.TOOL_EXECUTION_FAILED,
        errorMessage: msg,
        entitlement,
        decisionTrail
      };
    }

    try {
      const safeTarget = await NetworkValidator.validateSafeTarget(registeredTool.targetUrl);
      recordStage('TARGET_VALIDATION', 'PASS', `Validated target ${safeTarget}`);
    } catch (err: any) {
      const msg = redactSensitiveText(err?.message || 'Target URL blocked by SSRF policy.', this.rawLicenseKey);
      recordStage('TARGET_VALIDATION', 'FAIL', msg);
      return {
        success: false,
        errorCode: AgentGuardErrorCode.SSRF_OR_TARGET_BLOCKED,
        errorMessage: msg,
        entitlement,
        decisionTrail
      };
    }

    // 6. Atomic Budget Reservation via BurnBouncer
    let reservation: BurnReservation;
    try {
      reservation = this.bouncer.reserveExecution(request.projectedCostUsd);
      recordStage(
        'BUDGET_RESERVATION',
        'PASS',
        `Reserved ${reservation.costMicroUsd} micro-USD (reservationId=${reservation.reservationId})`
      );
    } catch (err: any) {
      const msg = redactSensitiveText(err?.message || 'Budget limit exceeded.', this.rawLicenseKey);
      recordStage('BUDGET_RESERVATION', 'FAIL', msg);
      return {
        success: false,
        errorCode: AgentGuardErrorCode.BUDGET_EXCEEDED,
        errorMessage: msg,
        entitlement,
        decisionTrail
      };
    }

    const compensateBudget = (reason: string): boolean => {
      const released = this.bouncer.releaseReservation(reservation.reservationId);
      recordStage(
        'BUDGET_RESERVATION',
        'COMPENSATED',
        `Released reservationId=${reservation.reservationId} (${reservation.costMicroUsd} micro-USD) due to: ${reason}`
      );
      return released;
    };

    // 7. MCP Tool Execution
    const toolResult = await this.gateway.handleRequest({
      requestId: request.idempotencyKey,
      agent: {
        id: agentId,
        role: request.agent.role,
        tenantId: request.agent.tenantId
      },
      toolName: request.toolName,
      arguments: request.arguments
    });

    if (!toolResult.success) {
      const errDetail = redactSensitiveText(toolResult.error || 'Tool execution failed.', this.rawLicenseKey);
      recordStage('TOOL_EXECUTION', 'FAIL', errDetail);
      const budgetCompensated = compensateBudget('tool execution failure');
      const errorCode =
        toolResult.error === 'Execution denied by human escrow.'
          ? AgentGuardErrorCode.ESCROW_APPROVAL_REQUIRED
          : AgentGuardErrorCode.TOOL_EXECUTION_FAILED;
      return {
        success: false,
        errorCode,
        errorMessage: errDetail,
        budgetCompensated,
        entitlement,
        toolResult,
        decisionTrail
      };
    }
    recordStage('TOOL_EXECUTION', 'PASS', `Tool ${request.toolName} succeeded`);

    // 8. Compute Receipt Signing & Verification (telemetry-witness)
    const receipt: ComputeReceipt =
      request.receipt ??
      this.receiptSigner.createReceipt({
        taskId: request.idempotencyKey,
        workloadId: request.toolName,
        workloadDescriptor: {
          toolName: registeredTool.name,
          method: registeredTool.method,
          targetUrl: registeredTool.targetUrl
        },
        inputData: request.arguments,
        executionTimeMs: Math.max(1, toolResult.latencyMs ?? 1)
      });

    const receiptVerification = this.receiptVerifier.verify(receipt);
    if (!receiptVerification.valid) {
      const reasonStr = receiptVerification.reasons.join(', ') || 'Receipt verification failed';
      recordStage('RECEIPT_VERIFICATION', 'FAIL', `Rejected receipt: ${reasonStr}`);
      const budgetCompensated = compensateBudget(`receipt verification failure (${reasonStr})`);
      return {
        success: false,
        errorCode: AgentGuardErrorCode.RECEIPT_VERIFICATION_FAILED,
        errorMessage: `Compute receipt verification failed: ${reasonStr}`,
        budgetCompensated,
        entitlement,
        toolResult,
        receipt,
        receiptVerification,
        decisionTrail
      };
    }
    recordStage(
      'RECEIPT_VERIFICATION',
      'PASS',
      `Verified receipt ${receipt.receiptId} (seq=${receipt.sequenceNumber})`
    );

    // 9. Payment Handshake Verification, Fee Calculation & Base L2 Settlement
    let feeSplit: FeeSplitResult | undefined;
    if (this.requirePayment && !request.payment) {
      const msg = 'Payment proof is required by guard policy.';
      recordStage('PAYMENT_VERIFICATION', 'FAIL', msg);
      const budgetCompensated = compensateBudget('missing required payment');
      return {
        success: false,
        errorCode: AgentGuardErrorCode.PAYMENT_VERIFICATION_FAILED,
        errorMessage: msg,
        budgetCompensated,
        entitlement,
        toolResult,
        receipt,
        receiptVerification,
        decisionTrail
      };
    }

    if (request.payment) {
      const paymentVerification = await this.paymentVerifier.verify(
        request.payment.paymentProofHeader,
        request.payment.policy,
        request.payment.binding
      );

      if (
        paymentVerification.state !== PaymentState.PAYMENT_VERIFIED ||
        !paymentVerification.payload
      ) {
        const reason = paymentVerification.reason || 'Payment verification failed';
        recordStage('PAYMENT_VERIFICATION', 'FAIL', reason);
        const budgetCompensated = compensateBudget(`payment verification failure (${reason})`);
        return {
          success: false,
          errorCode: AgentGuardErrorCode.PAYMENT_VERIFICATION_FAILED,
          errorMessage: `Payment verification failed: ${reason}`,
          budgetCompensated,
          entitlement,
          toolResult,
          receipt,
          receiptVerification,
          paymentVerification,
          decisionTrail
        };
      }
      recordStage(
        'PAYMENT_VERIFICATION',
        'PASS',
        `Verified x402 payment nonce=${paymentVerification.payload.nonce}`
      );

      const grossAmount =
        request.payment.grossAmountBaseUnits ??
        BigInt(paymentVerification.payload.amountBaseUnits ?? 0);
      const recipientForSplit = resolveFeeRecipient(
        this.feeRecipientHex ?? request.payment.policy.recipient
      );
      feeSplit = calculateFeeSplit(grossAmount, {
        tier: entitlement.tier,
        feeRecipient: recipientForSplit
      });

      if (request.payment.policy.settlementMode === SettlementMode.VERIFY_AND_SETTLE) {
        const settlementResult = await this.settlement.settle(
          paymentVerification.payload.transactionHash || '',
          grossAmount,
          request.payment.policy.recipient,
          { asset: paymentVerification.payload.asset }
        );
        if (!settlementResult.success) {
          const reason = settlementResult.error || 'On-chain settlement verification failed';
          recordStage('SETTLEMENT', 'FAIL', reason);
          const budgetCompensated = compensateBudget(`settlement failure (${reason})`);
          return {
            success: false,
            errorCode: AgentGuardErrorCode.SETTLEMENT_FAILED,
            errorMessage: `Base L2 settlement failed: ${reason}`,
            budgetCompensated,
            entitlement,
            feeSplit,
            toolResult,
            receipt,
            receiptVerification,
            paymentVerification,
            settlementResult,
            decisionTrail
          };
        }
        recordStage(
          'SETTLEMENT',
          'PASS',
          `Settled tx=${settlementResult.transactionHash} feeBps=${feeSplit.feeBps.toString()} fee=${feeSplit.protocolFee.toString()}`
        );

        // Commit budget reservation and cache idempotent outcome
        this.bouncer.commitReservation(reservation.reservationId);
        recordStage('FINALIZE', 'PASS', `Committed reservationId=${reservation.reservationId}`);

        const outcome: GuardExecutionOutcome = {
          success: true,
          entitlement,
          feeSplit,
          toolResult,
          receipt,
          receiptVerification,
          paymentVerification,
          settlementResult,
          decisionTrail
        };
        this.idempotencyCache.set(request.idempotencyKey, outcome);
        return outcome;
      }

      // VERIFY_ONLY payment mode
      this.bouncer.commitReservation(reservation.reservationId);
      recordStage('FINALIZE', 'PASS', `Committed reservationId=${reservation.reservationId}`);

      const outcome: GuardExecutionOutcome = {
        success: true,
        entitlement,
        feeSplit,
        toolResult,
        receipt,
        receiptVerification,
        paymentVerification,
        decisionTrail
      };
      this.idempotencyCache.set(request.idempotencyKey, outcome);
      return outcome;
    }

    // 10. Commit budget reservation when no payment step was required
    this.bouncer.commitReservation(reservation.reservationId);
    recordStage('FINALIZE', 'PASS', `Committed reservationId=${reservation.reservationId}`);

    const outcome: GuardExecutionOutcome = {
      success: true,
      entitlement,
      toolResult,
      receipt,
      receiptVerification,
      decisionTrail
    };
    this.idempotencyCache.set(request.idempotencyKey, outcome);
    return outcome;
  }

  public close(): void {
    if (this.closed) return;
    this.closed = true;
    this.bouncer.close();
    if ('close' in this.receiptStore && typeof (this.receiptStore as any).close === 'function') {
      (this.receiptStore as any).close();
    }
  }
}
