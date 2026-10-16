export { AgentGuard, type AgentGuardConfig } from './guard.js';
export {
  LemonSqueezyLicenseValidator,
  FetchLicenseHttpClient,
  LEMON_SQUEEZY_VALIDATE_URL,
  TIER_ENTITLEMENT_POLICIES,
  maskLicenseKey,
  type LemonSqueezyValidateResponse,
  type LicenseHttpClient,
  type LicenseHttpResponse,
  type LicenseValidatorConfig
} from './license.js';
export { AgentGuardError, AgentGuardErrorCode } from './errors.js';
export type {
  LicenseTier,
  TierEntitlementPolicy,
  ValidatedEntitlement,
  GuardAuditStage,
  GuardPaymentInput,
  GuardExecutionRequest,
  GuardExecutionOutcome,
  GuardToolRegistration
} from './types.js';

// Re-export key composed primitives for unified SDK consumers
export { BurnBouncer, type BouncerConfig, type BurnReservation } from '@digital-mineral/burn-bouncer';
export {
  McpGateway,
  SecureHttpExecutor,
  NetworkValidator,
  AuditLogger,
  PolicyEngine,
  RateLimiter,
  Role,
  type LegacyToolDefinition,
  type McpExecutionRequest,
  type McpExecutionResult
} from '@digital-mineral/mcp-bridge';
export {
  AgentEscrow,
  AgentAuthority,
  issueCapability,
  verifyCapability,
  calculateFeeSplit,
  validateFeeRecipient,
  FEE_TIER_BPS,
  type Capability,
  type FeeSplitResult
} from '@digital-mineral/agent-escrow';
export {
  NodeIdentity,
  NodeRegistry,
  SqliteReceiptStore,
  ReceiptSigner,
  ReceiptVerifier,
  type ComputeReceipt
} from '@digital-mineral/telemetry-witness';
export {
  HardenedPaymentVerifier,
  BaseL2PaymentSettlement,
  PaymentState,
  SettlementMode,
  type PaymentPolicy,
  type ResourceBinding,
  type SettlementResult
} from '@digital-mineral/agent-pay-handshake';
