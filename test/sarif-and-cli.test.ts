import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { formatMarkdown, formatSarif, formatText } from '../src/index.js';
import { scanPath } from '../src/scanner.js';

const ROOT = path.resolve(import.meta.dirname, '..');

describe('SARIF 2.1.0, Markdown formatting, and CLI behavior', () => {
  it('produces valid SARIF 2.1.0 JSON for vulnerable fixtures', () => {
    const summary = scanPath(path.join(ROOT, 'examples/vulnerable'), {
      compliance: ['uae-pdpl', 'desc-isr', 'soc2'],
    });
    const sarif = JSON.parse(formatSarif(summary)) as {
      version: string;
      runs: Array<{ tool: { driver: { rules: unknown[] } }; results: Array<{ ruleId: string; level: string }> }>;
    };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0]?.tool.driver.rules.length).toBe(15);
    expect(sarif.runs[0]?.results.length).toBe(summary.totalFindings);
    expect(sarif.runs[0]?.results.some((r) => r.level === 'error')).toBe(true);
  });

  it('formats clean Markdown table with UAE PDPL and DESC ISR references', () => {
    const summary = scanPath(path.join(ROOT, 'examples/vulnerable'), {
      compliance: ['uae-pdpl', 'desc-isr'],
    });
    const md = formatMarkdown(summary, ['uae-pdpl', 'desc-isr']);
    expect(md).toContain('UAE PDPL');
    expect(md).toContain('DESC ISR v3');
    expect(formatText(summary)).toContain('Scanned 3 file(s)');
  });

  it('exits 0 on hardened fixtures via CLI', () => {
    const stdout = execFileSync(
      'npx',
      ['tsx', 'src/cli.ts', '--input', 'examples/hardened', '--fail-on', 'medium'],
      { cwd: ROOT, encoding: 'utf8' },
    );
    expect(stdout).toContain('0 finding(s)');
  });
});
