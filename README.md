# owasp-agentic-policy-pack

**OWASP Top 10 for Agentic AI (2026) Policy Pack & Zero-LLM SARIF 2.1.0 CI Auditor** for Portkey OSS Gateway configs, Invariant-style runtime guardrails, and Model Context Protocol (`.mcp.json`) manifests — mapped directly to **UAE PDPL (Federal Decree-Law No. 45 of 2021)**, **Dubai DESC ISR v3**, and **SOC 2 Trust Services Criteria**.

> **Honest Scope Notice:** All bundled rules, CLI checks, and test suites execute locally on deterministic static rules and synthetic lab fixtures (`examples/vulnerable` vs `examples/hardened`). Truly Agentic is currently Pre-SOC 2; this repository provides engineering control mappings rather than third-party certification.

---

## Included Artifacts

| Path | Purpose |
| :--- | :--- |
| `policies/portkey/byoc-zero-retention.policy.json` | Portkey OSS gateway baseline enforcing zero data retention, provider allowlists, pre-flight cost/rate caps, scoped identity forwarding, and fail-closed WORM logging. |
| `policies/invariant/owasp-agentic.invariant.json` | Declarative Invariant-aligned guardrail rules for `ASI01`–`ASI10` (directive injection, wildcard tool block, manifest SHA-256 pinning, named individual approvers). |
| `compliance/uae-pdpl-desc-isr-map.json` | Structured control crosswalk (`ASI01`–`ASI10` -> UAE PDPL articles, Dubai DESC ISR v3 domains, and SOC 2 `CC5`–`CC9`). |
| `src/` (`owasp-agentic-audit` CLI) | Zero-runtime-dependency TypeScript static scanner outputting `text`, `json`, `markdown`, or **SARIF 2.1.0** for GitHub Code Scanning. |
| `examples/` | Reproducible `vulnerable/` (flagged) and `hardened/` (zero-finding) manifests for CI demos and regression testing. |

---

## Quickstart

Requires **Node.js >= 22** and **pnpm**:

```bash
pnpm install
pnpm run typecheck
pnpm test
pnpm run build
```

Run the auditor against the bundled synthetic fixtures:

```bash
# Passes with 0 findings (exit 0)
pnpm run audit:hardened

# Generates SARIF 2.1.0 output with UAE PDPL & DESC ISR v3 alignments
pnpm run audit:vulnerable > agentic-audit.sarif
```

CLI usage in your own CI pipeline (e.g., before uploading SARIF via `github/codeql-action/upload-sarif`):

```bash
owasp-agentic-audit \
  --input ./config \
  --format sarif \
  --fail-on high \
  --compliance uae-pdpl,desc-isr,soc2
```

---

## Related Open-Source & Architecture Links

- **Runtime Gateway Kit:** [`truly-agentic-governance-kit`](https://github.com/trulyagentic/truly-agentic-governance-kit) (Apache-2.0 runtime gateway, fail-closed Postgres ledger, Slack HMAC gate, AWS/GCP Terraform starters)
- **Documentation & Native MCP Server:** [`https://docs.trulyagentic.io`](https://docs.trulyagentic.io) (`https://docs.trulyagentic.io/mcp`)
- **Public Trust Center:** [`https://trust.trulyagentic.io`](https://trust.trulyagentic.io)
- **Website & Security Reporting:** [`https://trulyagentic.io/security`](https://trulyagentic.io/security) (`security@trulyagentic.io`)

Licensed under the [Apache License 2.0](./LICENSE).
