# Changelog

## v0.1.0 — 2026-11-25

- Initial Apache-2.0 release.
- Added Portkey BYOC zero-retention baseline policy (`policies/portkey/byoc-zero-retention.policy.json`) and Invariant-compatible guardrail pack (`policies/invariant/owasp-agentic.invariant.json`).
- Added UAE PDPL (Federal Decree-Law No. 45 of 2021), Dubai DESC ISR v3, and SOC 2 TSC mapping (`compliance/uae-pdpl-desc-isr-map.json`).
- Implemented deterministic 15-rule TypeScript static scanner (`src/scanner.ts`), SARIF 2.1.0 exporter (`src/sarif.ts`), Markdown reporter (`src/markdown-report.ts`), and `owasp-agentic-audit` CLI (`src/cli.ts`) with Vitest test suite covering vulnerable and hardened synthetic fixtures.
