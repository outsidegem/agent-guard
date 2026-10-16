# @digital-mineral/agent-guard

**Enterprise Runtime Firewall, Atomic Budget Circuit-Breaker, MCP Gateway, and Base L2 Settlement SDK for Autonomous AI Agents.**

Autonomous AI agents get stuck in retry loops, hallucinate tool arguments, and drain API budgets or crypto wallets in minutes. `@digital-mineral/agent-guard` sits *outside* the model and enforces deterministic, sub-millisecond security and financial invariants before any tool executes or settles on-chain.

---

## What's Inside the Unified Suite

* **Atomic Micro-USD Budget Firewall (`@digital-mineral/burn-bouncer`):** Two-phase budget reservation (`reserve` -> `commit` / `release`) backed by `node:sqlite` (`WAL` mode) using exact integer micro-USD math.
* **SSRF-Hardened MCP Gateway (`@digital-mineral/mcp-bridge`):** Role-based access control (RBAC), rate limiting, and strict IPv4/IPv6-mapped SSRF protection for Model Context Protocol (MCP) tools.
* **Cryptographic Capability Escrow (`@digital-mineral/agent-escrow`):** Single-use, constant-time HMAC capability tokens and human-in-the-loop state machines.
* **Verifiable Compute Receipts (`@digital-mineral/telemetry-witness`):** Ed25519-signed execution receipts with persistent SQLite nonce and monotonic sequence enforcement.
* **Base L2 On-Chain Settlement (`@digital-mineral/agent-pay-handshake`):** x402 payment verification and concrete Base Mainnet (`chainId: 8453`) ETH and USDC (`ERC-20 Transfer`) receipt validation.

---

## Quickstart (Node.js >= 22)

```bash
npm install @digital-mineral/agent-guard
```

```typescript
import { AgentGuard } from "@digital-mineral/agent-guard";

const guard = new AgentGuard({
  licenseKey: process.env.DMS_LICENSE_KEY,
  maxOpexLimitUsd: 5.00,
  rollingWindowMs: 3600_000,
});

const result = await guard.executeGuardedAction({
  idempotencyKey: "req-001",
  agentId: "agent-alpha",
  projectedCostUsd: 0.05,
  action: async () => ({ status: "executed" })
});
```

---

## Licensing & Pricing Tiers

| Tier | Concurrent Agents | Base L2 Escrow Fee | Price |
| :--- | :--- | :--- | :--- |
| **Community (Free)** | 1 Agent | 0.50% (50 bps) | **$0** (MIT) |
| **Pro / Startup** | Up to 25 Agents | 0.25% (25 bps) | **$149 / mo** |
| **Enterprise** | Unlimited Agents | 0.00% (0 bps) | **$3,499 / yr** |

👉 **Get a Pro or Enterprise License Key:** [scott@digitalmineralsolutions.com](mailto:scott@digitalmineralsolutions.com?subject=DMS%20Agent%20Guard%20License)

---
© 2026 Digital Mineral Solutions LLC. All rights reserved.
