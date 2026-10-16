import { createHash } from 'node:crypto';
import { AgentGuardError, AgentGuardErrorCode } from './errors.js';
import type { LicenseTier, TierEntitlementPolicy, ValidatedEntitlement } from './types.js';

export const LEMON_SQUEEZY_VALIDATE_URL = 'https://api.lemonsqueezy.com/v1/licenses/validate';

export const TIER_ENTITLEMENT_POLICIES: Readonly<Record<LicenseTier, TierEntitlementPolicy>> = Object.freeze({
  FREE: Object.freeze({
    tier: 'FREE',
    maxActiveAgents: 1,
    feeBps: 50n
  }),
  PRO: Object.freeze({
    tier: 'PRO',
    maxActiveAgents: 25,
    feeBps: 25n
  }),
  ENTERPRISE: Object.freeze({
    tier: 'ENTERPRISE',
    maxActiveAgents: Number.POSITIVE_INFINITY,
    feeBps: 0n
  })
});

export interface LemonSqueezyValidateResponse {
  valid: boolean;
  error: string | null;
  license_key?: {
    id: number;
    status: 'active' | 'inactive' | 'expired' | 'disabled' | string;
    key?: string;
    activation_limit?: number | null;
    activation_usage?: number;
    created_at?: string;
    expires_at?: string | null;
  } | null;
  instance?: {
    id: string;
    name: string;
    created_at: string;
  } | null;
  meta?: {
    store_id?: number;
    order_id?: number;
    order_item_id?: number;
    product_id?: number;
    product_name?: string;
    variant_id?: number;
    variant_name?: string;
    customer_id?: number;
  } | null;
}

export interface LicenseHttpResponse {
  status: number;
  ok: boolean;
  json(): Promise<unknown>;
}

export interface LicenseHttpClient {
  postForm(
    url: string,
    formBody: string,
    headers: Record<string, string>,
    timeoutMs: number
  ): Promise<LicenseHttpResponse>;
}

export class FetchLicenseHttpClient implements LicenseHttpClient {
  async postForm(
    url: string,
    formBody: string,
    headers: Record<string, string>,
    timeoutMs: number
  ): Promise<LicenseHttpResponse> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers,
        body: formBody,
        signal: controller.signal,
        redirect: 'error'
      });
      return {
        status: res.status,
        ok: res.ok,
        json: () => res.json()
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

export interface LicenseValidatorConfig {
  /** License key to validate; falls back to `process.env.LEMON_SQUEEZY_LICENSE_KEY`. */
  licenseKey?: string;
  /** Optional Lemon Squeezy instance ID; falls back to `process.env.LEMON_SQUEEZY_INSTANCE_ID`. */
  instanceId?: string;
  /** Validation endpoint URL. Defaults to `https://api.lemonsqueezy.com/v1/licenses/validate`. */
  endpointUrl?: string;
  /** Expected Lemon Squeezy `store_id` for cross-store key rejection. */
  expectedStoreId?: number;
  /** Expected Lemon Squeezy `product_id` for cross-product key rejection. */
  expectedProductId?: number;
  /** Maps Lemon Squeezy `variant_id` numbers to trusted `LicenseTier` levels. */
  variantIdToTier?: Record<number, LicenseTier>;
  /** Injectable HTTP client for deterministic offline testing. */
  httpClient?: LicenseHttpClient;
  /** HTTP request timeout in milliseconds. Default 5000. */
  timeoutMs?: number;
  /** Cache TTL in milliseconds for validated entitlements. Default 60000 (0 disables caching). */
  cacheTtlMs?: number;
  /**
   * Policy when no license key is supplied:
   * - `true` (default): resolve to `FREE` tier (1 agent, 50 bps).
   * - `false`: throw `LICENSE_INVALID`.
   */
  allowUnlicensedFreeTier?: boolean;
  /**
   * Policy when network/provider is unreachable:
   * - `'FAIL_CLOSED'` (default): reject validation with `LICENSE_VERIFICATION_FAILED`.
   * - `'DOWNGRADE_FREE'`: fall back strictly to `FREE` tier (never PRO or ENTERPRISE).
   */
  offlinePolicy?: 'FAIL_CLOSED' | 'DOWNGRADE_FREE';
}

/** Masks a license key so sensitive key material is never logged or persisted in plain text. */
export function maskLicenseKey(rawKey?: string | null): string {
  if (!rawKey || typeof rawKey !== 'string') return 'UNLICENSED';
  const trimmed = rawKey.trim();
  if (trimmed.length <= 8) return '****';
  return `${trimmed.slice(0, 4)}...${trimmed.slice(-4)}`;
}

function resolveTierFromMeta(
  meta: LemonSqueezyValidateResponse['meta'],
  variantMap?: Record<number, LicenseTier>
): LicenseTier {
  if (meta?.variant_id !== undefined && variantMap && variantMap[meta.variant_id]) {
    return variantMap[meta.variant_id];
  }
  const variantName = (meta?.variant_name || '').toUpperCase();
  if (variantName.includes('ENTERPRISE')) return 'ENTERPRISE';
  if (variantName.includes('PRO')) return 'PRO';
  return 'FREE';
}

export class LemonSqueezyLicenseValidator {
  private readonly endpointUrl: string;
  private readonly httpClient: LicenseHttpClient;
  private readonly timeoutMs: number;
  private readonly cacheTtlMs: number;
  private readonly allowUnlicensedFreeTier: boolean;
  private readonly offlinePolicy: 'FAIL_CLOSED' | 'DOWNGRADE_FREE';
  private cachedEntitlement: { entitlement: ValidatedEntitlement; expiresAtMs: number; keyHash: string } | null = null;

  constructor(private readonly config: LicenseValidatorConfig = {}) {
    this.endpointUrl = config.endpointUrl || LEMON_SQUEEZY_VALIDATE_URL;
    this.httpClient = config.httpClient || new FetchLicenseHttpClient();
    this.timeoutMs = Math.max(500, Math.floor(config.timeoutMs ?? 5000));
    this.cacheTtlMs = Math.max(0, Math.floor(config.cacheTtlMs ?? 60_000));
    this.allowUnlicensedFreeTier = config.allowUnlicensedFreeTier ?? true;
    this.offlinePolicy = config.offlinePolicy ?? 'FAIL_CLOSED';
  }

  public invalidateCache(): void {
    this.cachedEntitlement = null;
  }

  public getPolicyForTier(tier: LicenseTier): TierEntitlementPolicy {
    if (!Object.prototype.hasOwnProperty.call(TIER_ENTITLEMENT_POLICIES, tier)) {
      throw new AgentGuardError(AgentGuardErrorCode.LICENSE_INVALID, `Unknown license tier: ${String(tier)}`);
    }
    return TIER_ENTITLEMENT_POLICIES[tier];
  }

  public async validate(overrideLicenseKey?: string, overrideInstanceId?: string): Promise<ValidatedEntitlement> {
    const rawKey = (overrideLicenseKey ?? this.config.licenseKey ?? process.env.LEMON_SQUEEZY_LICENSE_KEY ?? '').trim();
    const instanceId = (
      overrideInstanceId ??
      this.config.instanceId ??
      process.env.LEMON_SQUEEZY_INSTANCE_ID ??
      ''
    ).trim();

    if (!rawKey) {
      if (!this.allowUnlicensedFreeTier) {
        throw new AgentGuardError(
          AgentGuardErrorCode.LICENSE_INVALID,
          'License key is required when unlicensed FREE tier is disabled.'
        );
      }
      const freePolicy = TIER_ENTITLEMENT_POLICIES.FREE;
      return {
        ...freePolicy,
        valid: true,
        status: 'unlicensed_free',
        maskedKey: 'UNLICENSED',
        validatedAt: Date.now(),
        expiresAt: null
      };
    }

    const now = Date.now();
    const keyHash = createHash('sha256').update(rawKey).digest('hex');
    if (
      this.cachedEntitlement &&
      this.cachedEntitlement.keyHash === keyHash &&
      now < this.cachedEntitlement.expiresAtMs
    ) {
      return this.cachedEntitlement.entitlement;
    }

    const params = new URLSearchParams();
    params.set('license_key', rawKey);
    if (instanceId) {
      params.set('instance_id', instanceId);
    }

    let httpRes: LicenseHttpResponse;
    try {
      httpRes = await this.httpClient.postForm(
        this.endpointUrl,
        params.toString(),
        {
          Accept: 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        this.timeoutMs
      );
    } catch (err: any) {
      return this.handleProviderFailure(
        `License validation request failed (${err?.name === 'AbortError' ? 'timeout' : 'network error'}).`
      );
    }

    if (httpRes.status === 429) {
      return this.handleProviderFailure('Lemon Squeezy license API rate limit exceeded (HTTP 429).');
    }

    let body: LemonSqueezyValidateResponse;
    try {
      body = (await httpRes.json()) as LemonSqueezyValidateResponse;
    } catch {
      return this.handleProviderFailure('Malformed JSON response from Lemon Squeezy license endpoint.');
    }

    if (!body || typeof body !== 'object' || typeof body.valid !== 'boolean') {
      return this.handleProviderFailure('Invalid response schema from Lemon Squeezy license endpoint.');
    }

    const keyStatus = body.license_key?.status;
    if (keyStatus === 'expired') {
      throw new AgentGuardError(AgentGuardErrorCode.LICENSE_EXPIRED, 'License key has expired.');
    }
    if (keyStatus === 'disabled') {
      throw new AgentGuardError(AgentGuardErrorCode.LICENSE_REVOKED, 'License key has been disabled or revoked.');
    }

    if (body.license_key?.expires_at) {
      const expMs = Date.parse(body.license_key.expires_at);
      if (!Number.isNaN(expMs) && expMs <= Date.now()) {
        throw new AgentGuardError(AgentGuardErrorCode.LICENSE_EXPIRED, 'License key expiration timestamp has passed.');
      }
    }

    if (!httpRes.ok || !body.valid || body.error !== null || (keyStatus !== 'active' && keyStatus !== 'inactive')) {
      throw new AgentGuardError(
        AgentGuardErrorCode.LICENSE_INVALID,
        `License key validation failed: ${body.error || 'invalid license'}.`
      );
    }

    const expectedStore =
      this.config.expectedStoreId ??
      (process.env.LEMON_SQUEEZY_STORE_ID ? Number(process.env.LEMON_SQUEEZY_STORE_ID) : undefined);
    if (expectedStore !== undefined && body.meta?.store_id !== expectedStore) {
      throw new AgentGuardError(
        AgentGuardErrorCode.LICENSE_INVALID,
        'License key store_id does not match expected store.'
      );
    }

    const expectedProduct =
      this.config.expectedProductId ??
      (process.env.LEMON_SQUEEZY_PRODUCT_ID ? Number(process.env.LEMON_SQUEEZY_PRODUCT_ID) : undefined);
    if (expectedProduct !== undefined && body.meta?.product_id !== expectedProduct) {
      throw new AgentGuardError(
        AgentGuardErrorCode.LICENSE_INVALID,
        'License key product_id does not match expected product.'
      );
    }

    const resolvedTier = resolveTierFromMeta(body.meta, this.config.variantIdToTier);
    const tierPolicy = TIER_ENTITLEMENT_POLICIES[resolvedTier];
    const expiresAt = body.license_key?.expires_at ? Date.parse(body.license_key.expires_at) : null;

    const entitlement: ValidatedEntitlement = {
      ...tierPolicy,
      valid: true,
      status: 'active',
      maskedKey: maskLicenseKey(rawKey),
      validatedAt: Date.now(),
      expiresAt: expiresAt && !Number.isNaN(expiresAt) ? expiresAt : null,
      storeId: body.meta?.store_id,
      productId: body.meta?.product_id,
      variantId: body.meta?.variant_id
    };

    if (this.cacheTtlMs > 0) {
      const cacheExpiry = entitlement.expiresAt
        ? Math.min(Date.now() + this.cacheTtlMs, entitlement.expiresAt)
        : Date.now() + this.cacheTtlMs;
      this.cachedEntitlement = {
        entitlement,
        expiresAtMs: cacheExpiry,
        keyHash
      };
    }

    return entitlement;
  }

  private handleProviderFailure(reason: string): ValidatedEntitlement {
    if (this.offlinePolicy === 'DOWNGRADE_FREE') {
      const freePolicy = TIER_ENTITLEMENT_POLICIES.FREE;
      return {
        ...freePolicy,
        valid: true,
        status: 'unlicensed_free',
        maskedKey: 'OFFLINE_FREE',
        validatedAt: Date.now(),
        expiresAt: null
      };
    }
    throw new AgentGuardError(AgentGuardErrorCode.LICENSE_VERIFICATION_FAILED, reason);
  }
}
