import type { ComplianceFramework, ScanSummary } from './types.js';

export function formatMarkdown(
  summary: ScanSummary,
  frameworks: readonly ComplianceFramework[] = [],
): string {
  const lines: string[] = [
    '# OWASP Agentic AI Policy Audit Report',
    '',
    `- **Scanned Files:** \`${summary.scannedFiles}\``,
    `- **Total Findings:** \`${summary.totalFindings}\` (critical: \`${summary.bySeverity.critical}\`, high: \`${summary.bySeverity.high}\`, medium: \`${summary.bySeverity.medium}\`, low: \`${summary.bySeverity.low}\`)`,
  ];
  if (frameworks.length > 0) {
    lines.push(`- **Compliance Crosswalk:** \`${frameworks.join(', ')}\``);
  }
  lines.push('');

  if (summary.findings.length === 0) {
    lines.push('All inspected AI gateway, MCP, and agent manifests passed zero-finding policy checks.');
    return lines.join('\n');
  }

  lines.push('| Rule | OWASP | Severity | Location | Finding | Compliance Alignment |');
  lines.push('| :--- | :--- | :--- | :--- | :--- | :--- |');
  for (const f of summary.findings) {
    const refs: string[] = [];
    if (f.compliance) {
      if (frameworks.includes('uae-pdpl')) refs.push(`UAE PDPL: ${f.compliance.uaePdpl.join('; ')}`);
      if (frameworks.includes('desc-isr')) refs.push(`DESC ISR v3: ${f.compliance.descIsrV3.join('; ')}`);
      if (frameworks.includes('soc2')) refs.push(`SOC 2: ${f.compliance.soc2Tsc.join(', ')}`);
    }
    const cleanMsg = f.message.replace(/\|/g, '\\|');
    lines.push(`| \`${f.ruleId}\` | \`${f.owaspId}\` | **${f.severity}** | \`${f.file}:${f.line}\` | ${cleanMsg} | ${refs.join(' / ') || '—'} |`);
  }
  return lines.join('\n');
}

export function formatText(summary: ScanSummary): string {
  const header = `Scanned ${summary.scannedFiles} file(s): ${summary.totalFindings} finding(s) [critical=${summary.bySeverity.critical}, high=${summary.bySeverity.high}, medium=${summary.bySeverity.medium}, low=${summary.bySeverity.low}]`;
  if (summary.findings.length === 0) return header;
  const rows = summary.findings.map(
    (f) => `- [${f.severity.toUpperCase()}] ${f.ruleId} (${f.owaspId}) ${f.file}:${f.line} — ${f.message}`,
  );
  return `${header}\n${rows.join('\n')}`;
}
