import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import {
  AgentGuard,
  AgentGuardErrorCode,
  issueCapability,
  LemonSqueezyLicenseValidator,
  Role,
  SettlementMode,
  type LemonSqueezyValidateResponse,
  type LicenseHttpClient,
  type LicenseHttpResponse,
  type LegacyToolDefinition,
  type PaymentPolicy,
  type ResourceBinding
} from '../src/index.js';

const TEST_PRIVATE_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const TEST_RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
const TEST_TX_HASH = '0x' + 'a'.repeat(64);
const SECRET_LICENSE_KEY = 'LSQ-SUPER-SECRET-KEY-9999-ABCD';

function createMockLicenseClient(
  responder: (url: string, formBody: string) => Promise<{ status?: number; ok?: boolean; body: unknown }>
): LicenseHttpClient {
  return {
    async postForm(url: string, formBody: string): Promise<LicenseHttpResponse> {
      const res = await responder(url, formBody);
      const status = res.status ?? 200;
      const ok = res.ok ?? (status >= 200 && status < 300);
      return {
        status,
        ok,
        json: async () => res.body
      };
    }
  };
}

function makeLemonResponse(
  overrides: Partial<LemonSqueezyValidateResponse> & { variantName?: string; variantId?: number; status?: string } = {}
): LemonSqueezyValidateResponse {
  return {
    valid: overrides.valid ?? true,
    error: overrides.error ?? null,
    license_key:
      overrides.license_key !== undefined
        ? overrides.license_key
        : {
            id: 101,
            status: overrides.status ?? 'active',
            key: SECRET_LICENSE_KEY,
            activation_limit: 5,
            activation_usage: 1,
            expires_at: null
          },
    instance: null,
    meta:
      overrides.meta !== undefined
        ? overrides.meta
        : {
            store_id: 1000,
            product_id: 2000,
            variant_id: overrides.variantId ?? 3001,
            variant_name: overrides.variantName ?? 'Pro Plan'
          }
  };
}

const SAFE_TOOL: LegacyToolDefinition = {
  name: 'fetch_mineral_quote',
  description: 'Fetch mineral quote over HTTPS',
  targetUrl: 'https://8.8.8.8/api/v1/quote',
  method: 'GET',
  inputSchema: {
    type: 'object',
    properties: {
      symbol: { type: 'string' }
    },
    required: ['symbol']
  }
};

async function createSignedPaymentProof(params: {
  recipient?: string;
  amountBaseUnits?: bigint;
  asset?: string;
  chainId?: number;
  nonce?: string;
  transactionHash?: string;
  resource?: string;
  timestamp?: number;
}) {
  const account = privateKeyToAccount(TEST_PRIVATE_KEY);
  const payload = {
    recipient: params.recipient ?? TEST_RECIPIENT,
    amountBaseUnits: (params.amountBaseUnits ?? 10_000n).toString(),
    asset: params.asset ?? 'ETH',
    chainId: params.chainId ?? 8453,
    nonce: params.nonce ?? `pay-nonce-${Math.random().toString(36).slice(2)}`,
    transactionHash: params.transactionHash ?? TEST_TX_HASH,
    resource: params.resource ?? '/tools/fetch_mineral_quote',
    timestamp: params.timestamp ?? Date.now()
  };
  const signature = await account.signMessage({
    message: JSON.stringify(payload)
  });
  const fullPayload = {
    ...payload,
    payer: account.address,
    signature
  };
  return Buffer.from(JSON.stringify(fullPayload), 'utf-8').toString('base64');
}

describe('@digital-mineral/agent-guard Unified SDK & Security Suite', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(async () =>
        new Response(JSON.stringify({ quoteUsd: 42.5, status: 'ok' }), {
          status: 200,
          headers: { 'content-type': 'application/json' }
        })
      )
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('1. Enforces FREE tier entitlements: 1 active agent max and 50 bps protocol fee', async () => {
    const guard = new AgentGuard({
      license: {
        licenseKey: SECRET_LICENSE_KEY,
        httpClient: createMockLicenseClient(async () => ({
          body: makeLemonResponse({ variantName: 'Free Community' })
        }))
      },
      feeRecipientHex: TEST_RECIPIENT
    });
    guard.registerTool(SAFE_TOOL, Role.ADMIN);

    const first = await guard.execute({
      idempotencyKey: 'req-free-1',
      agent: { id: 'agent-1', role: Role.AGENT, tenantId: 'tenant-a' },
      toolName: SAFE_TOOL.name,
      arguments: { symbol: 'LI' },
      projectedCostUsd: 0.25
    });

    expect(first.success).toBe(true);
    expect(first.entitlement?.tier).toBe('FREE');
    expect(first.entitlement?.maxActiveAgents).toBe(1);
    expect(first.entitlement?.feeBps).toBe(50n);

    const split = guard.calculateTierFeeSplit(10_000n, first.entitlement!);
    expect(split.protocolFee).toBe(50n);
    expect(split.netAmount).toBe(9_950n);

    // Second distinct agent must be rejected on FREE tier
    const second = await guard.execute({
      idempotencyKey: 'req-free-2',
      agent: { id: 'agent-2', role: Role.AGENT, tenantId: 'tenant-a' },
      toolName: SAFE_TOOL.name,
      arguments: { symbol: 'LI' },
      projectedCostUsd: 0.25
    });

    expect(second.success).toBe(false);
    expect(second.errorCode).toBe(AgentGuardErrorCode.AGENT_QUOTA_EXCEEDED);
    guard.close();
  });

  it('2. Enforces PRO tier entitlements: up to 25 active agents and 25 bps protocol fee', async () => {
    const guard = new AgentGuard({
      license: {
        licenseKey: SECRET_LICENSE_KEY,
        httpClient: createMockLicenseClient(async () => ({
          body: makeLemonResponse({ variantName: 'Pro Tier' })
        }))
      },
      bouncer: { maxOpexLimit: 1000, rollingWindowMs: 60_000, storagePath: ':memory:' },
      feeRecipientHex: TEST_RECIPIENT
    });
    guard.registerTool(SAFE_TOOL, Role.ADMIN);

    for (let i = 1; i <= 25; i++) {
      const res = await guard.execute({
        idempotencyKey: `req-pro-${i}`,
        agent: { id: `agent-${i}`, role: Role.AGENT, tenantId: 'tenant-a' },
        toolName: SAFE_TOOL.name,
        arguments: { symbol: 'CO' },
        projectedCostUsd: 0.1
      });
      expect(res.success).toBe(true);
      expect(res.entitlement?.tier).toBe('PRO');
      expect(res.entitlement?.feeBps).toBe(25n);
    }

    // 26th distinct agent must be rejected on PRO tier
    const overflow = await guard.execute({
      idempotencyKey: 'req-pro-26',
      agent: { id: 'agent-26', role: Role.AGENT, tenantId: 'tenant-a' },
      toolName: SAFE_TOOL.name,
      arguments: { symbol: 'CO' },
      projectedCostUsd: 0.1
    });
    expect(overflow.success).toBe(false);
    expect(overflow.errorCode).toBe(AgentGuardErrorCode.AGENT_QUOTA_EXCEEDED);
    guard.close();
  });

  it('3. Enforces ENTERPRISE tier entitlements: unlimited agents (>25) and 0 bps protocol fee', async () => {
    const guard = new AgentGuard({
      license: {
        licenseKey: SECRET_LICENSE_KEY,
        httpClient: createMockLicenseClient(async () => ({
          body: makeLemonResponse({ variantName: 'Enterprise Unlimited' })
        }))
      },
      bouncer: { maxOpexLimit: 1000, rollingWindowMs: 60_000, storagePath: ':memory:' },
      feeRecipientHex: TEST_RECIPIENT
    });
    guard.registerTool(SAFE_TOOL, Role.ADMIN);

    for (let i = 1; i <= 27; i++) {
      const res = await guard.execute({
        idempotencyKey: `req-ent-${i}`,
        agent: { id: `ent-agent-${i}`, role: Role.AGENT, tenantId: 'tenant-ent' },
        toolName: SAFE_TOOL.name,
        arguments: { symbol: 'AU' },
        projectedCostUsd: 0.05
      });
      expect(res.success).toBe(true);
      expect(res.entitlement?.tier).toBe('ENTERPRISE');
      expect(res.entitlement?.feeBps).toBe(0n);
    }

    const entitlement = await guard.licenseValidator.validate();
    const split = guard.calculateTierFeeSplit(500_000n, entitlement);
    expect(split.protocolFee).toBe(0n);
    expect(split.netAmount).toBe(500_000n);
    guard.close();
  });

  it('4. Rejects invalid, expired, and disabled/revoked Lemon Squeezy license keys', async () => {
    const expiredGuard = new AgentGuard({
      license: {
        licenseKey: SECRET_LICENSE_KEY,
        httpClient: createMockLicenseClient(async () => ({
          body: makeLemonResponse({ status: 'expired', valid: false })
        }))
      }
    });
    expiredGuard.registerTool(SAFE_TOOL, Role.ADMIN);
    const expiredRes = await expiredGuard.execute({
      idempotencyKey: 'req-exp',
      agent: { id: 'a1', role: Role.AGENT, tenantId: 't1' },
      toolName: SAFE_TOOL.name,
      arguments: { symbol: 'LI' },
      projectedCostUsd: 0.1
    });
    expect(expiredRes.success).toBe(false);
    expect(expiredRes.errorCode).toBe(AgentGuardErrorCode.LICENSE_EXPIRED);
    expiredGuard.close();

    const revokedGuard = new AgentGuard({
      license: {
        licenseKey: SECRET_LICENSE_KEY,
        httpClient: createMockLicenseClient(async () => ({
          body: makeLemonResponse({ status: 'disabled', valid: false })
        }))
      }
    });
    revokedGuard.registerTool(SAFE_TOOL, Role.ADMIN);
    const revokedRes = await revokedGuard.execute({
      idempotencyKey: 'req-rev',
      agent: { id: 'a1', role: Role.AGENT, tenantId: 't1' },
      toolName: SAFE_TOOL.name,
      arguments: { symbol: 'LI' },
      projectedCostUsd: 0.1
    });
    expect(revokedRes.success).toBe(false);
    expect(revokedRes.errorCode).toBe(AgentGuardErrorCode.LICENSE_REVOKED);
    revokedGuard.close();

    const invalidGuard = new AgentGuard({
      license: {
        licenseKey: SECRET_LICENSE_KEY,
        httpClient: createMockLicenseClient(async () => ({
          status: 404,
          ok: false,
          body: { valid: false, error: 'license_key not found' }
        }))
      }
    });
    invalidGuard.registerTool(SAFE_TOOL, Role.ADMIN);
    const invalidRes = await invalidGuard.execute({
      idempotencyKey: 'req-inv',
      agent: { id: 'a1', role: Role.AGENT, tenantId: 't1' },
      toolName: SAFE_TOOL.name,
      arguments: { symbol: 'LI' },
      projectedCostUsd: 0.1
    });
    expect(invalidRes.success).toBe(false);
    expect(invalidRes.errorCode).toBe(AgentGuardErrorCode.LICENSE_INVALID);
    invalidGuard.close();
  });

  it('5. Fails closed on provider timeout/429/malformed response and never grants elevated tier offline', async () => {
    const failClosedValidator = new LemonSqueezyLicenseValidator({
      licenseKey: SECRET_LICENSE_KEY,
      offlinePolicy: 'FAIL_CLOSED',
      httpClient: createMockLicenseClient(async () => ({
        status: 429,
        ok: false,
        body: { error: 'rate limit' }
      }))
    });
    await expect(failClosedValidator.validate()).rejects.toMatchObject({
      code: AgentGuardErrorCode.LICENSE_VERIFICATION_FAILED
    });

    const downgradeValidator = new LemonSqueezyLicenseValidator({
      licenseKey: SECRET_LICENSE_KEY,
      offlinePolicy: 'DOWNGRADE_FREE',
      httpClient: createMockLicenseClient(async () => {
        throw new Error('Network unreachable');
      })
    });
    const fallbackEntitlement = await downgradeValidator.validate();
    expect(fallbackEntitlement.tier).toBe('FREE');
    expect(fallbackEntitlement.feeBps).toBe(50n);
    expect(fallbackEntitlement.maxActiveAgents).toBe(1);
  });

  it('6. Prevents client-supplied tier spoofing (claimedTier="ENTERPRISE" ignored when license is FREE)', async () => {
    const guard = new AgentGuard({
      license: {
        allowUnlicensedFreeTier: true
      },
      feeRecipientHex: TEST_RECIPIENT
    });
    guard.registerTool(SAFE_TOOL, Role.ADMIN);

    const proof = await createSignedPaymentProof({ amountBaseUnits: 10_000n });
    const policy: PaymentPolicy = {
      priceBaseUnits: 10_000n,
      maxPaymentBaseUnits: 100_000n,
      recipient: TEST_RECIPIENT,
      acceptedChainIds: [8453],
      acceptedAssets: ['ETH'],
      expirationWindowMs: 60_000,
      settlementMode: SettlementMode.VERIFY_ONLY
    };
    const binding: ResourceBinding = { path: '/tools/fetch_mineral_quote', method: 'GET' };

    const outcome = await guard.execute({
      idempotencyKey: 'spoof-attempt-1',
      agent: {
        id: 'spoofing-agent',
        role: Role.AGENT,
        tenantId: 'tenant-1',
        claimedTier: 'ENTERPRISE'
      },
      toolName: SAFE_TOOL.name,
      arguments: { symbol: 'LI' },
      projectedCostUsd: 0.5,
      payment: {
        paymentProofHeader: proof,
        policy,
        binding
      }
    });

    expect(outcome.success).toBe(true);
    expect(outcome.entitlement?.tier).toBe('FREE');
    expect(outcome.feeSplit?.feeBps).toBe(50n);
    expect(outcome.feeSplit?.protocolFee).toBe(50n);
    expect(
      outcome.decisionTrail.some(
        (s) => s.stage === 'LICENSE' && s.detail.includes('ignored untrusted claimedTier=ENTERPRISE')
      )
    ).toBe(true);
    guard.close();
  });

  it('7. Rejects cross-store and cross-product Lemon Squeezy license keys', async () => {
    const validator = new LemonSqueezyLicenseValidator({
      licenseKey: SECRET_LICENSE_KEY,
      expectedStoreId: 1000,
      expectedProductId: 2000,
      httpClient: createMockLicenseClient(async () => ({
        body: makeLemonResponse({
          meta: { store_id: 1000, product_id: 9999, variant_id: 3001, variant_name: 'Enterprise' }
        })
      }))
    });

    await expect(validator.validate()).rejects.toMatchObject({
      code: AgentGuardErrorCode.LICENSE_INVALID
    });
  });

  it('8. Executes full end-to-end happy path across all 5 packages including Base L2 settlement', async () => {
    const mockSettlement = {
      settle: vi.fn().mockResolvedValue({
        success: true,
        transactionHash: TEST_TX_HASH,
        status: 'success',
        blockNumber: 120n,
        confirmations: 3n,
        chainId: 8453,
        asset: 'ETH',
        settledAmount: 10_000n,
        recipient: TEST_RECIPIENT.toLowerCase()
      })
    };

    const guard = new AgentGuard({
      license: {
        licenseKey: SECRET_LICENSE_KEY,
        httpClient: createMockLicenseClient(async () => ({
          body: makeLemonResponse({ variantName: 'Pro Plan' })
        }))
      },
      bouncer: { maxOpexLimit: 10.0, rollingWindowMs: 60_000, storagePath: ':memory:' },
      settlement: mockSettlement,
      feeRecipientHex: TEST_RECIPIENT
    });
    guard.registerTool(SAFE_TOOL, Role.ADMIN);

    const capability = issueCapability(
      'agent-pro-1',
      'act-1',
      'hash-1',
      'READ',
      SAFE_TOOL.name,
      60_000
    );
    const proof = await createSignedPaymentProof({ amountBaseUnits: 10_000n });
    const policy: PaymentPolicy = {
      priceBaseUnits: 10_000n,
      maxPaymentBaseUnits: 100_000n,
      recipient: TEST_RECIPIENT,
      acceptedChainIds: [8453],
      acceptedAssets: ['ETH'],
      expirationWindowMs: 60_000,
      settlementMode: SettlementMode.VERIFY_AND_SETTLE
    };
    const binding: ResourceBinding = { path: '/tools/fetch_mineral_quote', method: 'GET' };

    const outcome = await guard.execute({
      idempotencyKey: 'e2e-happy-1',
      agent: { id: 'agent-pro-1', role: Role.AGENT, tenantId: 'tenant-pro' },
      toolName: SAFE_TOOL.name,
      arguments: { symbol: 'CU' },
      projectedCostUsd: 1.25,
      capability,
      payment: {
        paymentProofHeader: proof,
        policy,
        binding
      }
    });

    expect(outcome.success).toBe(true);
    expect(outcome.entitlement?.tier).toBe('PRO');
    expect(outcome.feeSplit?.feeBps).toBe(25n);
    expect(outcome.feeSplit?.protocolFee).toBe(25n);
    expect(outcome.feeSplit?.netAmount).toBe(9_975n);
    expect(outcome.receiptVerification?.valid).toBe(true);
    expect(outcome.settlementResult?.success).toBe(true);
    expect(guard.bouncer.getCurrentBurnMicro()).toBe(1_250_000);
    guard.close();
  });

  it('9. Blocks SSRF targets (including IPv4-mapped IPv6 loopback) before reserving budget', async () => {
    const guard = new AgentGuard({
      bouncer: { maxOpexLimit: 10, rollingWindowMs: 60_000, storagePath: ':memory:' }
    });
    guard.registerTool(
      {
        ...SAFE_TOOL,
        name: 'ssrf_tool',
        targetUrl: 'https://[::ffff:127.0.0.1]/internal'
      },
      Role.ADMIN
    );

    const outcome = await guard.execute({
      idempotencyKey: 'ssrf-1',
      agent: { id: 'agent-1', role: Role.AGENT, tenantId: 'tenant-1' },
      toolName: 'ssrf_tool',
      arguments: { symbol: 'LI' },
      projectedCostUsd: 2.5
    });

    expect(outcome.success).toBe(false);
    expect(outcome.errorCode).toBe(AgentGuardErrorCode.SSRF_OR_TARGET_BLOCKED);
    expect(guard.bouncer.getCurrentBurnMicro()).toBe(0);
    guard.close();
  });

  it('10. Rejects execution when BurnBouncer budget ceiling would be exceeded', async () => {
    const guard = new AgentGuard({
      bouncer: { maxOpexLimit: 1.0, rollingWindowMs: 60_000, storagePath: ':memory:' }
    });
    guard.registerTool(SAFE_TOOL, Role.ADMIN);

    const outcome = await guard.execute({
      idempotencyKey: 'budget-overflow-1',
      agent: { id: 'agent-1', role: Role.AGENT, tenantId: 'tenant-1' },
      toolName: SAFE_TOOL.name,
      arguments: { symbol: 'LI' },
      projectedCostUsd: 1.000001
    });

    expect(outcome.success).toBe(false);
    expect(outcome.errorCode).toBe(AgentGuardErrorCode.BUDGET_EXCEEDED);
    expect(guard.bouncer.getCurrentBurnMicro()).toBe(0);
    guard.close();
  });

  it('11. Releases reserved budget when MCP tool execution fails downstream', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response('Upstream 500', { status: 500 }))
    );

    const guard = new AgentGuard({
      bouncer: { maxOpexLimit: 10.0, rollingWindowMs: 60_000, storagePath: ':memory:' }
    });
    guard.registerTool(SAFE_TOOL, Role.ADMIN);

    const outcome = await guard.execute({
      idempotencyKey: 'tool-fail-1',
      agent: { id: 'agent-1', role: Role.AGENT, tenantId: 'tenant-1' },
      toolName: SAFE_TOOL.name,
      arguments: { symbol: 'LI' },
      projectedCostUsd: 3.5
    });

    expect(outcome.success).toBe(false);
    expect(outcome.errorCode).toBe(AgentGuardErrorCode.TOOL_EXECUTION_FAILED);
    expect(outcome.budgetCompensated).toBe(true);
    expect(guard.bouncer.getCurrentBurnMicro()).toBe(0);
    guard.close();
  });

  it('12. Releases reserved budget when compute receipt verification fails (tampered signature or replay)', async () => {
    const guard = new AgentGuard({
      bouncer: { maxOpexLimit: 10.0, rollingWindowMs: 60_000, storagePath: ':memory:' }
    });
    guard.registerTool(SAFE_TOOL, Role.ADMIN);

    const tamperedReceipt = guard.receiptSigner.createReceipt({
      taskId: 'tampered-1',
      workloadId: SAFE_TOOL.name,
      workloadDescriptor: {},
      inputData: {},
      executionTimeMs: 10
    });
    tamperedReceipt.signature = '00'.repeat(64);

    const outcome = await guard.execute({
      idempotencyKey: 'receipt-fail-1',
      agent: { id: 'agent-1', role: Role.AGENT, tenantId: 'tenant-1' },
      toolName: SAFE_TOOL.name,
      arguments: { symbol: 'LI' },
      projectedCostUsd: 2.0,
      receipt: tamperedReceipt
    });

    expect(outcome.success).toBe(false);
    expect(outcome.errorCode).toBe(AgentGuardErrorCode.RECEIPT_VERIFICATION_FAILED);
    expect(outcome.budgetCompensated).toBe(true);
    expect(guard.bouncer.getCurrentBurnMicro()).toBe(0);
    guard.close();
  });

  it('13. Releases reserved budget when payment verification or Base L2 settlement fails', async () => {
    const failingSettlement = {
      settle: vi.fn().mockResolvedValue({
        success: false,
        transactionHash: TEST_TX_HASH,
        error: 'Transaction reverted on Base L2'
      })
    };

    const guard = new AgentGuard({
      bouncer: { maxOpexLimit: 10.0, rollingWindowMs: 60_000, storagePath: ':memory:' },
      settlement: failingSettlement,
      feeRecipientHex: TEST_RECIPIENT
    });
    guard.registerTool(SAFE_TOOL, Role.ADMIN);

    const proof = await createSignedPaymentProof({ amountBaseUnits: 10_000n });
    const policy: PaymentPolicy = {
      priceBaseUnits: 10_000n,
      maxPaymentBaseUnits: 100_000n,
      recipient: TEST_RECIPIENT,
      acceptedChainIds: [8453],
      acceptedAssets: ['ETH'],
      expirationWindowMs: 60_000,
      settlementMode: SettlementMode.VERIFY_AND_SETTLE
    };
    const binding: ResourceBinding = { path: '/tools/fetch_mineral_quote', method: 'GET' };

    const outcome = await guard.execute({
      idempotencyKey: 'settle-fail-1',
      agent: { id: 'agent-1', role: Role.AGENT, tenantId: 'tenant-1' },
      toolName: SAFE_TOOL.name,
      arguments: { symbol: 'LI' },
      projectedCostUsd: 4.0,
      payment: {
        paymentProofHeader: proof,
        policy,
        binding
      }
    });

    expect(outcome.success).toBe(false);
    expect(outcome.errorCode).toBe(AgentGuardErrorCode.SETTLEMENT_FAILED);
    expect(outcome.budgetCompensated).toBe(true);
    expect(guard.bouncer.getCurrentBurnMicro()).toBe(0);
    guard.close();
  });

  it('14. Enforces idempotency on duplicate idempotencyKey without double-charging budget or re-executing tool', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ quoteUsd: 42.5 }), { status: 200 })
    );
    vi.stubGlobal('fetch', fetchSpy);

    const guard = new AgentGuard({
      bouncer: { maxOpexLimit: 10.0, rollingWindowMs: 60_000, storagePath: ':memory:' }
    });
    guard.registerTool(SAFE_TOOL, Role.ADMIN);

    const req = {
      idempotencyKey: 'idem-key-100',
      agent: { id: 'agent-1', role: Role.AGENT, tenantId: 'tenant-1' },
      toolName: SAFE_TOOL.name,
      arguments: { symbol: 'LI' },
      projectedCostUsd: 1.5
    };

    const first = await guard.execute(req);
    const second = await guard.execute(req);

    expect(first.success).toBe(true);
    expect(second.success).toBe(true);
    expect(second.replayedIdempotent).toBe(true);
    expect(second.receipt?.receiptId).toBe(first.receipt?.receiptId);
    expect(guard.bouncer.getCurrentBurnMicro()).toBe(1_500_000);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    guard.close();
  });

  it('15. Redacts license keys and bearer tokens from decisionTrail and enforces close() lifecycle', async () => {
    const guard = new AgentGuard({
      license: {
        licenseKey: SECRET_LICENSE_KEY,
        httpClient: createMockLicenseClient(async () => ({
          body: makeLemonResponse({ variantName: 'Pro Plan' })
        }))
      }
    });
    guard.registerTool(SAFE_TOOL, Role.ADMIN);

    const outcome = await guard.execute({
      idempotencyKey: 'redact-test-1',
      agent: { id: 'agent-1', role: Role.AGENT, tenantId: 'tenant-1' },
      toolName: SAFE_TOOL.name,
      arguments: { symbol: 'LI' },
      projectedCostUsd: 0.1
    });

    expect(outcome.success).toBe(true);
    const serializedTrail = JSON.stringify(outcome.decisionTrail);
    expect(serializedTrail).not.toContain(SECRET_LICENSE_KEY);
    expect(serializedTrail).toContain('LSQ-...ABCD');

    guard.close();
    const afterClose = await guard.execute({
      idempotencyKey: 'after-close-1',
      agent: { id: 'agent-1', role: Role.AGENT, tenantId: 'tenant-1' },
      toolName: SAFE_TOOL.name,
      arguments: { symbol: 'LI' },
      projectedCostUsd: 0.1
    });
    expect(afterClose.success).toBe(false);
    expect(afterClose.errorCode).toBe(AgentGuardErrorCode.GUARD_CLOSED);
  });
});
