import type { OwaspAsiId, PolicyRuleMeta } from './types.js';

export const SEVERITY_RANK = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
} as const;

export const RULES: Record<string, PolicyRuleMeta> = {
  'TA-ASI01-001': {
    id: 'TA-ASI01-001',
    owaspId: 'ASI01',
    severity: 'critical',
    title: 'Prompt injection or override directive detected',
    description:
      'Tool descriptions or prompts contain directive injection markers such as <IMPORTANT> or instruction-override phrases.',
    remediation: 'Remove imperative directives from schemas/prompts and enforce policy in typed gateway code.',
  },
  'TA-ASI02-001': {
    id: 'TA-ASI02-001',
    owaspId: 'ASI02',
    severity: 'high',
    title: 'Wildcard tool or permission scope',
    description: 'Configuration grants wildcard (*) tool or action access instead of explicit least-privilege allowlists.',
    remediation: 'Replace wildcard allowlists with explicit enumerated tool and action names.',
  },
  'TA-ASI02-002': {
    id: 'TA-ASI02-002',
    owaspId: 'ASI02',
    severity: 'high',
    title: 'Sensitive write tool lacks typed policy ceilings',
    description: 'Write or financial tools are configured without explicit policyCeilings or numeric parameter caps.',
    remediation: 'Configure policyCeilings (e.g., maxAmountUsd, allowedCurrencies, allowedDomains) on write tools.',
  },
  'TA-ASI03-001': {
    id: 'TA-ASI03-001',
    owaspId: 'ASI03',
    severity: 'critical',
    title: 'Hardcoded secret or shared/personal admin identity',
    description:
      'Artifact contains likely hardcoded API keys/secrets or assigns personal/shared admin identities instead of scoped service accounts.',
    remediation: 'Move credentials to KMS/Secrets Manager references and bind workloads to dedicated service accounts.',
  },
  'TA-ASI03-002': {
    id: 'TA-ASI03-002',
    owaspId: 'ASI03',
    severity: 'high',
    title: 'Missing scoped service identity forwarding',
    description: 'Gateway or agent config omits dedicated serviceAccountId or disables forwardClientIdentity.',
    remediation: 'Set explicit serviceAccountId and set forwardClientIdentity: true and rejectSharedAdminAccounts: true.',
  },
  'TA-ASI04-001': {
    id: 'TA-ASI04-001',
    owaspId: 'ASI04',
    severity: 'critical',
    title: 'Unpinned MCP server or mutable remote execution',
    description:
      'MCP server entry lacks a SHA-256 manifest pin or executes unpinned mutable package tags (e.g., npx -y without version/sha256).',
    remediation: 'Pin each MCP server manifest with a verified sha256 digest and lock package versions.',
  },
  'TA-ASI04-002': {
    id: 'TA-ASI04-002',
    owaspId: 'ASI04',
    severity: 'high',
    title: 'Insecure non-TLS remote MCP or gateway URL',
    description: 'Remote server or endpoint uses plaintext http:// outside loopback localhost/127.0.0.1.',
    remediation: 'Require https:// with valid TLS certificates for all non-loopback network endpoints.',
  },
  'TA-ASI05-001': {
    id: 'TA-ASI05-001',
    owaspId: 'ASI05',
    severity: 'critical',
    title: 'Unrestricted code or shell execution enabled',
    description: 'Agent enables shell/eval/command tools or sets allowShellExecution: true without isolated sandboxing.',
    remediation: 'Disable shell execution tools or isolate inside restricted ephemeral containers with read-only mounts.',
  },
  'TA-ASI06-001': {
    id: 'TA-ASI06-001',
    owaspId: 'ASI06',
    severity: 'high',
    title: 'Unisolated agent memory or unsanitized external writes',
    description: 'Persistent agent memory omits strict per-tenant isolation or disables external write sanitization.',
    remediation: 'Enforce memory.isolation = "per-tenant" and memory.sanitizeExternalWrites = true.',
  },
  'TA-ASI06-002': {
    id: 'TA-ASI06-002',
    owaspId: 'ASI06',
    severity: 'high',
    title: 'Zero-data-retention inference guarantee missing',
    description: 'AI gateway config lacks zeroDataRetention: true or permits provider training (allowProviderTraining: true).',
    remediation: 'Set dataGovernance.zeroDataRetention = true and allowProviderTraining = false on BYOC VPC endpoints.',
  },
  'TA-ASI07-001': {
    id: 'TA-ASI07-001',
    owaspId: 'ASI07',
    severity: 'medium',
    title: 'Unauthenticated inter-agent messaging',
    description: 'Multi-agent section omits cryptographic signature verification (requireSignedMessages: true).',
    remediation: 'Enable HMAC or mTLS message verification across agent-to-agent boundaries.',
  },
  'TA-ASI08-001': {
    id: 'TA-ASI08-001',
    owaspId: 'ASI08',
    severity: 'high',
    title: 'Missing or excessive pre-flight budget and retry caps',
    description: 'Gateway/agent lacks hard cost/rate bounds (maxCostUsd, maxRequestsPerMinute) or allows >3 retries.',
    remediation: 'Configure strict maxCostUsd, maxRequestsPerMinute, requestTimeoutMs, and maxRetries <= 3.',
  },
  'TA-ASI09-001': {
    id: 'TA-ASI09-001',
    owaspId: 'ASI09',
    severity: 'critical',
    title: 'Write actions lack named individual human approval gate',
    description:
      'Agent declares write/mutate capabilities without required individual human sign-off or allows shared inbox approval.',
    remediation: 'Set humanApproval.required = true with allowGroupInboxApproval = false.',
  },
  'TA-ASI10-001': {
    id: 'TA-ASI10-001',
    owaspId: 'ASI10',
    severity: 'high',
    title: 'Audit logging is not fail-closed or lacks kill-switch TTL',
    description: 'Gateway/agent permits execution when audit logging fails or omits killSwitchTtlSeconds.',
    remediation: 'Enable audit.failClosed = true, audit.appendOnly = true, and configure killSwitchTtlSeconds.',
  },
  'TA-NET-001': {
    id: 'TA-NET-001',
    owaspId: 'ASI05',
    severity: 'medium',
    title: 'Gateway runtime binds publicly to 0.0.0.0',
    description: 'Local or BYOC gateway runtime binds to 0.0.0.0 instead of loopback 127.0.0.1 or private VPC interface.',
    remediation: 'Bind gateway listeners to 127.0.0.1 behind private VPC or WireGuard/Tailscale tunnels.',
  },
};

export function getComplianceRef(
  owaspId: OwaspAsiId,
  mapData: Record<string, { owaspName: string; uaePdpl: string[]; descIsrV3: string[]; soc2Tsc: string[] }>,
) {
  return mapData[owaspId];
}
