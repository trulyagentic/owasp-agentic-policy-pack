import { RULES } from './rules.js';
import type { ScanSummary, Severity } from './types.js';

function mapSarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

export function formatSarif(summary: ScanSummary): string {
  const rules = Object.values(RULES).map((r) => ({
    id: r.id,
    name: r.title,
    shortDescription: { text: `${r.owaspId}: ${r.title}` },
    fullDescription: { text: r.description },
    help: { text: r.remediation },
    properties: {
      tags: ['security', 'owasp-agentic-ai', r.owaspId.toLowerCase()],
      'security-severity': r.severity === 'critical' ? '9.5' : r.severity === 'high' ? '8.0' : r.severity === 'medium' ? '5.5' : '3.0',
    },
  }));

  const results = summary.findings.map((f) => ({
    ruleId: f.ruleId,
    level: mapSarifLevel(f.severity),
    message: {
      text: `${f.message} Remediation: ${f.remediation}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file },
          region: { startLine: f.line },
        },
      },
    ],
    properties: {
      owaspId: f.owaspId,
      severity: f.severity,
      ...(f.compliance ? { compliance: f.compliance } : {}),
    },
  }));

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'owasp-agentic-policy-pack',
            version: '0.1.0',
            informationUri: 'https://github.com/trulyagentic/owasp-agentic-policy-pack',
            rules,
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
