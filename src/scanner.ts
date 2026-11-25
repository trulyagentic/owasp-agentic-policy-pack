import fs from 'node:fs';
import path from 'node:path';
import { RULES } from './rules.js';
import type {
  ComplianceFramework,
  ComplianceRef,
  Finding,
  OwaspAsiId,
  ScanOptions,
  ScanSummary,
} from './types.js';

const PROMPT_INJECTION_RE =
  /<IMPORTANT>|ignore\s+previous\s+instructions|disregard\s+prior\s+rules|system\s+prompt\s+override|exfiltrate\s+(?:secrets|tokens|env)/i;
const SECRET_RE =
  /(?:sk-[a-zA-Z0-9_-]{16,}|ghp_[a-zA-Z0-9]{20,}|cfat_[a-zA-Z0-9_-]{16,}|xoxb-[a-zA-Z0-9-]{16,}|AKIA[0-9A-Z]{16})/;
const SHARED_ADMIN_RE = /^(admin|root|superuser|team@|ops@|finance@|all@)/i;
const SHELL_TOOL_RE = /\b(bash|sh|shell|exec|eval|cmd|powershell|python_exec|run_command)\b/i;
const WRITE_TOOL_RE = /(write|pay|transfer|wire|delete|drop|approve|invoice|refund|mutate|update|create)/i;

type ComplianceMap = Record<OwaspAsiId, ComplianceRef>;

function loadDefaultComplianceMap(): ComplianceMap {
  const candidates = [
    path.resolve(import.meta.dirname, '..', 'compliance', 'uae-pdpl-desc-isr-map.json'),
    path.resolve(process.cwd(), 'compliance', 'uae-pdpl-desc-isr-map.json'),
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) {
      const parsed = JSON.parse(fs.readFileSync(p, 'utf8')) as { mappings: ComplianceMap };
      return parsed.mappings;
    }
  }
  return {} as ComplianceMap;
}

const COMPLIANCE_MAP = loadDefaultComplianceMap();

function findLineNumber(rawText: string, needle: string): number {
  if (!needle) return 1;
  const idx = rawText.indexOf(needle);
  if (idx === -1) return 1;
  return rawText.slice(0, idx).split('\n').length;
}

function addFinding(
  out: Finding[],
  ruleId: string,
  file: string,
  rawText: string,
  needle: string,
  message: string,
  compliance?: readonly ComplianceFramework[],
): void {
  const meta = RULES[ruleId];
  if (!meta) return;
  const ref = compliance && compliance.length > 0 ? COMPLIANCE_MAP[meta.owaspId] : undefined;
  out.push({
    ruleId: meta.id,
    owaspId: meta.owaspId,
    severity: meta.severity,
    title: meta.title,
    message,
    file,
    line: findLineNumber(rawText, needle),
    remediation: meta.remediation,
    ...(ref ? { compliance: ref } : {}),
  });
}

function walkStrings(obj: unknown, keyPath = ''): Array<{ keyPath: string; value: string }> {
  if (typeof obj === 'string') return [{ keyPath, value: obj }];
  if (Array.isArray(obj)) {
    return obj.flatMap((item, idx) => walkStrings(item, `${keyPath}[${idx}]`));
  }
  if (obj && typeof obj === 'object') {
    return Object.entries(obj).flatMap(([k, v]) => walkStrings(v, keyPath ? `${keyPath}.${k}` : k));
  }
  return [];
}

function scanCommonStrings(
  obj: unknown,
  file: string,
  rawText: string,
  out: Finding[],
  compliance?: readonly ComplianceFramework[],
): void {
  for (const { keyPath, value } of walkStrings(obj)) {
    if (PROMPT_INJECTION_RE.test(value) && !/^guardrails\[\d+\]\.patterns\[\d+\]$/.test(keyPath)) {
      addFinding(
        out,
        'TA-ASI01-001',
        file,
        rawText,
        value.slice(0, 32),
        `Directive/prompt-injection pattern detected at "${keyPath}".`,
        compliance,
      );
    }
    if (SECRET_RE.test(value)) {
      addFinding(
        out,
        'TA-ASI03-001',
        file,
        rawText,
        value.slice(0, 12),
        `Potential hardcoded API token or secret detected at "${keyPath}".`,
        compliance,
      );
    }
    if (/^http:\/\/(?!localhost\b|127\.0\.0\.1\b|\[::1\])/i.test(value)) {
      addFinding(
        out,
        'TA-ASI04-002',
        file,
        rawText,
        value,
        `Non-TLS remote endpoint "${value}" found at "${keyPath}".`,
        compliance,
      );
    }
    if (value === '0.0.0.0' && /bind|host|listen/i.test(keyPath)) {
      addFinding(
        out,
        'TA-NET-001',
        file,
        rawText,
        '0.0.0.0',
        `Public network bind 0.0.0.0 configured at "${keyPath}".`,
        compliance,
      );
    }
  }
}

function scanMcpManifest(
  doc: Record<string, unknown>,
  file: string,
  rawText: string,
  out: Finding[],
  compliance?: readonly ComplianceFramework[],
): void {
  const servers = (doc.mcpServers ?? doc.servers) as Record<string, Record<string, unknown>> | undefined;
  if (!servers || typeof servers !== 'object') return;

  for (const [serverName, cfg] of Object.entries(servers)) {
    if (!cfg || typeof cfg !== 'object') continue;
    const pin = cfg.sha256 ?? cfg.manifestSha256 ?? cfg.digest;
    if (typeof pin !== 'string' || !/^[a-f0-9]{64}$/i.test(pin)) {
      addFinding(
        out,
        'TA-ASI04-001',
        file,
        rawText,
        serverName,
        `MCP server "${serverName}" has no 64-char SHA-256 manifest pin.`,
        compliance,
      );
    }
    const args = Array.isArray(cfg.args) ? cfg.args.join(' ') : '';
    const cmd = typeof cfg.command === 'string' ? `${cfg.command} ${args}` : '';
    if (/\bnpx\b.*(?:-y|--yes).*@(?:latest|\*)|\bnpx\b\s+-y\s+[a-z0-9_/-]+(?:\s|$)/i.test(cmd)) {
      addFinding(
        out,
        'TA-ASI04-001',
        file,
        rawText,
        serverName,
        `MCP server "${serverName}" launches unpinned npx package ("${cmd.trim()}").`,
        compliance,
      );
    }
    const allowedTools = Array.isArray(cfg.allowedTools) ? cfg.allowedTools : [];
    for (const tool of allowedTools) {
      const toolStr = String(tool);
      if (toolStr === '*' || toolStr === '*:*' || toolStr.toLowerCase() === 'all') {
        addFinding(
          out,
          'TA-ASI02-001',
          file,
          rawText,
          toolStr,
          `MCP server "${serverName}" grants wildcard tool access ("${toolStr}").`,
          compliance,
        );
      }
      if (SHELL_TOOL_RE.test(toolStr)) {
        addFinding(
          out,
          'TA-ASI05-001',
          file,
          rawText,
          toolStr,
          `MCP server "${serverName}" exposes unrestricted shell/exec tool "${toolStr}".`,
          compliance,
        );
      }
    }
  }
}

function scanGatewayOrAgentConfig(
  doc: Record<string, unknown>,
  file: string,
  rawText: string,
  out: Finding[],
  compliance?: readonly ComplianceFramework[],
): void {
  const isPortkey = 'dataGovernance' in doc || 'allowedProviders' in doc || 'budgetsAndLimits' in doc;
  const isAgent = 'tools' in doc || 'agentId' in doc || 'humanApproval' in doc || 'memory' in doc;
  if (!isPortkey && !isAgent) return;

  const dg = (doc.dataGovernance ?? {}) as Record<string, unknown>;
  if (isPortkey && (dg.zeroDataRetention !== true || dg.allowProviderTraining === true)) {
    addFinding(
      out,
      'TA-ASI06-002',
      file,
      rawText,
      'dataGovernance',
      'Gateway dataGovernance does not enforce zeroDataRetention: true and allowProviderTraining: false.',
      compliance,
    );
  }

  const identity = (doc.identity ?? {}) as Record<string, unknown>;
  const serviceAccount =
    typeof identity.serviceAccountId === 'string'
      ? identity.serviceAccountId
      : typeof doc.serviceAccountId === 'string'
        ? doc.serviceAccountId
        : '';
  if (!serviceAccount || identity.forwardClientIdentity === false || identity.rejectSharedAdminAccounts === false) {
    addFinding(
      out,
      'TA-ASI03-002',
      file,
      rawText,
      serviceAccount || 'identity',
      'Missing scoped serviceAccountId or identity forwarding controls.',
      compliance,
    );
  }
  if (serviceAccount && SHARED_ADMIN_RE.test(serviceAccount)) {
    addFinding(
      out,
      'TA-ASI03-001',
      file,
      rawText,
      serviceAccount,
      `Shared or personal admin account "${serviceAccount}" is disallowed for agent runtime.`,
      compliance,
    );
  }

  const budgets = (doc.budgetsAndLimits ?? doc.budgets ?? {}) as Record<string, unknown>;
  const hasCostCap = typeof budgets.maxCostUsd === 'number' && budgets.maxCostUsd > 0;
  const hasRateCap = typeof budgets.maxRequestsPerMinute === 'number' && budgets.maxRequestsPerMinute > 0;
  const badRetries = typeof budgets.maxRetries === 'number' && budgets.maxRetries > 3;
  if (!hasCostCap || !hasRateCap || badRetries) {
    addFinding(
      out,
      'TA-ASI08-001',
      file,
      rawText,
      'budgets',
      'Missing maxCostUsd/maxRequestsPerMinute caps or maxRetries exceeds safe limit (>3).',
      compliance,
    );
  }

  const audit = (doc.audit ?? {}) as Record<string, unknown>;
  if (audit.failClosed !== true || audit.appendOnly !== true || typeof audit.killSwitchTtlSeconds !== 'number') {
    addFinding(
      out,
      'TA-ASI10-001',
      file,
      rawText,
      'audit',
      'Audit configuration must set failClosed: true, appendOnly: true, and numeric killSwitchTtlSeconds.',
      compliance,
    );
  }

  if (isAgent) {
    if (doc.allowShellExecution === true) {
      addFinding(
        out,
        'TA-ASI05-001',
        file,
        rawText,
        'allowShellExecution',
        'Agent manifest enables allowShellExecution: true.',
        compliance,
      );
    }

    const tools = Array.isArray(doc.tools) ? doc.tools : [];
    let hasWriteTool = false;
    for (const rawTool of tools) {
      const toolName = typeof rawTool === 'string' ? rawTool : String((rawTool as Record<string, unknown>)?.name ?? '');
      if (toolName === '*' || toolName === '*:*' || toolName.toLowerCase() === 'all') {
        addFinding(out, 'TA-ASI02-001', file, rawText, toolName, 'Agent declares wildcard tool access "*".', compliance);
      }
      if (SHELL_TOOL_RE.test(toolName)) {
        addFinding(
          out,
          'TA-ASI05-001',
          file,
          rawText,
          toolName,
          `Agent manifest includes unrestricted shell/exec tool "${toolName}".`,
          compliance,
        );
      }
      if (WRITE_TOOL_RE.test(toolName)) {
        hasWriteTool = true;
      }
    }

    const ceilings = doc.policyCeilings as Record<string, unknown> | undefined;
    if (hasWriteTool && (!ceilings || Object.keys(ceilings).length === 0)) {
      addFinding(
        out,
        'TA-ASI02-002',
        file,
        rawText,
        'tools',
        'Write/mutating tools configured without typed policyCeilings.',
        compliance,
      );
    }

    const approval = (doc.humanApproval ?? {}) as Record<string, unknown>;
    if (hasWriteTool && (approval.required !== true || approval.allowGroupInboxApproval === true)) {
      addFinding(
        out,
        'TA-ASI09-001',
        file,
        rawText,
        'humanApproval',
        'Write-capable agent must require individual human approval (allowGroupInboxApproval: false).',
        compliance,
      );
    }

    const memory = doc.memory as Record<string, unknown> | undefined;
    if (memory && (memory.isolation !== 'per-tenant' || memory.sanitizeExternalWrites !== true)) {
      addFinding(
        out,
        'TA-ASI06-001',
        file,
        rawText,
        'memory',
        'Persistent agent memory must enforce isolation: "per-tenant" and sanitizeExternalWrites: true.',
        compliance,
      );
    }

    const multiAgent = doc.multiAgent as Record<string, unknown> | undefined;
    if (multiAgent && multiAgent.enabled === true && multiAgent.requireSignedMessages !== true) {
      addFinding(
        out,
        'TA-ASI07-001',
        file,
        rawText,
        'multiAgent',
        'Multi-agent communication enabled without requireSignedMessages: true.',
        compliance,
      );
    }
  }
}

export function scanJsonContent(
  rawText: string,
  filePath: string,
  options: ScanOptions = {},
): readonly Finding[] {
  const findings: Finding[] = [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch (err) {
    addFinding(
      findings,
      'TA-ASI04-001',
      filePath,
      rawText,
      '',
      `Invalid JSON manifest (${(err as Error).message}).`,
      options.compliance,
    );
    return findings;
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return findings;
  }
  const doc = parsed as Record<string, unknown>;
  scanCommonStrings(doc, filePath, rawText, findings, options.compliance);
  scanMcpManifest(doc, filePath, rawText, findings, options.compliance);
  scanGatewayOrAgentConfig(doc, filePath, rawText, findings, options.compliance);
  return findings;
}

function collectJsonFiles(targetPath: string): string[] {
  const abs = path.resolve(targetPath);
  const stat = fs.statSync(abs);
  if (stat.isFile()) return [abs];
  const results: string[] = [];
  for (const entry of fs.readdirSync(abs, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === '.git') continue;
    const full = path.join(abs, entry.name);
    if (entry.isDirectory()) {
      results.push(...collectJsonFiles(full));
    } else if (entry.isFile() && entry.name.endsWith('.json')) {
      results.push(full);
    }
  }
  return results.sort();
}

export function scanPath(targetPath: string, options: ScanOptions = {}): ScanSummary {
  const files = collectJsonFiles(targetPath);
  const allFindings: Finding[] = [];
  for (const absFile of files) {
    const rel = path.relative(process.cwd(), absFile) || path.basename(absFile);
    const raw = fs.readFileSync(absFile, 'utf8');
    allFindings.push(...scanJsonContent(raw, rel, options));
  }

  const bySeverity = {
    critical: allFindings.filter((f) => f.severity === 'critical').length,
    high: allFindings.filter((f) => f.severity === 'high').length,
    medium: allFindings.filter((f) => f.severity === 'medium').length,
    low: allFindings.filter((f) => f.severity === 'low').length,
  };

  return {
    scannedFiles: files.length,
    totalFindings: allFindings.length,
    bySeverity,
    findings: allFindings,
  };
}
