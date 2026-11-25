import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { scanJsonContent, scanPath } from '../src/scanner.js';

const ROOT = path.resolve(import.meta.dirname, '..');

describe('owasp-agentic-policy-pack static scanner (synthetic fixtures)', () => {
  it('flags zero findings on hardened reference manifests and policy pack', () => {
    const summary = scanPath(path.join(ROOT, 'examples/hardened'), {
      compliance: ['uae-pdpl', 'desc-isr', 'soc2'],
    });
    expect(summary.scannedFiles).toBe(3);
    expect(summary.totalFindings).toBe(0);
  });

  it('passes bundled baseline policies under policies/', () => {
    const summary = scanPath(path.join(ROOT, 'policies'), {
      compliance: ['uae-pdpl', 'desc-isr'],
    });
    expect(summary.scannedFiles).toBe(2);
    expect(summary.totalFindings).toBe(0);
  });

  it('detects all targeted OWASP Agentic AI risks in vulnerable fixtures', () => {
    const summary = scanPath(path.join(ROOT, 'examples/vulnerable'), {
      compliance: ['uae-pdpl', 'desc-isr', 'soc2'],
    });
    const ruleIds = new Set(summary.findings.map((f) => f.ruleId));
    expect(summary.bySeverity.critical).toBeGreaterThanOrEqual(4);
    expect(ruleIds.has('TA-ASI01-001')).toBe(true);
    expect(ruleIds.has('TA-ASI02-001')).toBe(true);
    expect(ruleIds.has('TA-ASI02-002')).toBe(true);
    expect(ruleIds.has('TA-ASI03-001')).toBe(true);
    expect(ruleIds.has('TA-ASI03-002')).toBe(true);
    expect(ruleIds.has('TA-ASI04-001')).toBe(true);
    expect(ruleIds.has('TA-ASI04-002')).toBe(true);
    expect(ruleIds.has('TA-ASI05-001')).toBe(true);
    expect(ruleIds.has('TA-ASI06-001')).toBe(true);
    expect(ruleIds.has('TA-ASI06-002')).toBe(true);
    expect(ruleIds.has('TA-ASI07-001')).toBe(true);
    expect(ruleIds.has('TA-ASI08-001')).toBe(true);
    expect(ruleIds.has('TA-ASI09-001')).toBe(true);
    expect(ruleIds.has('TA-ASI10-001')).toBe(true);
    expect(ruleIds.has('TA-NET-001')).toBe(true);
    expect(summary.findings[0]?.compliance?.uaePdpl.length).toBeGreaterThan(0);
    expect(summary.findings[0]?.compliance?.descIsrV3.length).toBeGreaterThan(0);
  });

  it('flags hardcoded secrets inside arbitrary JSON fields', () => {
    const findings = scanJsonContent(
      JSON.stringify({ apiKey: 'sk-test1234567890abcdef12345' }),
      'inline-secret.json',
    );
    expect(findings.some((f) => f.ruleId === 'TA-ASI03-001')).toBe(true);
  });
});
