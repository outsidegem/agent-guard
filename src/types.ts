import type { Capability, FeeSplitResult } from '@digital-mineral/agent-escrow';
import type {
  PaymentPolicy,
  ResourceBinding,
  SettlementResult,
  VerificationResult as PaymentVerificationResult
} from '@digital-mineral/agent-pay-handshake';
import type { LegacyToolDefinition, McpExecutionResult, Role } from '@digital-mineral/mcp-bridge';
import type { ComputeReceipt, VerificationResult as ReceiptVerificationResult } from '@digital-mineral/telemetry-witness';
import type { AgentGuardErrorCode } from './errors.js';

export type LicenseTier = 'FREE' | 'PRO' | 'ENTERPRISE';

export interface TierEntitlementPolicy {
  tier: LicenseTier;
  /** Maximum concurrent/registered agents allowed (`Infinity` for ENTERPRISE). */
  maxActiveAgents: number;
  /** Protocol fee basis points (`50n` FREE, `25n` PRO, `0n` ENTERPRISE). */
  feeBps: bigint;
}

export interface ValidatedEntitlement extends TierEntitlementPolicy {
  valid: boolean;
  status: 'active' | 'expired' | 'disabled' | 'inactive' | 'unlicensed_free';
  maskedKey: string;
  validatedAt: number;
  expiresAt: number | null;
  storeId?: number;
  productId?: number;
  variantId?: number;
}

export interface GuardAuditStage {
  stage:
    | 'IDEMPOTENCY'
    | 'LICENSE'
    | 'AGENT_QUOTA'
    | 'CAPABILITY'
    | 'TARGET_VALIDATION'
    | 'BUDGET_RESERVATION'
    | 'TOOL_EXECUTION'
    | 'RECEIPT_VERIFICATION'
    | 'PAYMENT_VERIFICATION'
    | 'SETTLEMENT'
    | 'FINALIZE';
  status: 'PASS' | 'FAIL' | 'COMPENSATED' | 'REPLAYED';
  timestamp: number;
  detail: string;
}

export interface GuardPaymentInput {
  paymentProofHeader: string;
  policy: PaymentPolicy;
  binding: ResourceBinding;
  grossAmountBaseUnits?: bigint;
}

export interface GuardExecutionRequest {
  idempotencyKey: string;
  agent: {
    id: string;
    role: Role;
    tenantId: string;
    /** Ignored for security decisions; tier is always resolved from validated license entitlement. */
    claimedTier?: string;
  };
  toolName: string;
  arguments: Record<string, unknown>;
  projectedCostUsd: number;
  /** Optional pre-issued capability from AgentEscrow/AgentAuthority. */
  capability?: Capability;
  /** Optional pre-signed compute receipt; if omitted, AgentGuard signs and verifies one on execution. */
  receipt?: ComputeReceipt;
  /** Optional x402 payment & Base L2 settlement parameters. */
  payment?: GuardPaymentInput;
}

export interface GuardExecutionOutcome {
  success: boolean;
  replayedIdempotent?: boolean;
  errorCode?: AgentGuardErrorCode;
  errorMessage?: string;
  budgetCompensated?: boolean;
  entitlement?: ValidatedEntitlement;
  feeSplit?: FeeSplitResult;
  toolResult?: McpExecutionResult;
  receipt?: ComputeReceipt;
  receiptVerification?: ReceiptVerificationResult;
  paymentVerification?: PaymentVerificationResult;
  settlementResult?: SettlementResult;
  decisionTrail: GuardAuditStage[];
}

export interface GuardToolRegistration {
  tool: LegacyToolDefinition;
  registrarRole?: Role;
}
