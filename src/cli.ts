#!/usr/bin/env node
import { formatMarkdown, formatText } from './markdown-report.js';
import { SEVERITY_RANK } from './rules.js';
import { formatSarif } from './sarif.js';
import { scanPath } from './scanner.js';
import type { ComplianceFramework, Severity } from './types.js';

interface CliArgs {
  input: string;
  format: 'text' | 'json' | 'sarif' | 'markdown';
  failOn: Severity | 'none';
  compliance: ComplianceFramework[];
  help: boolean;
}

function parseCliArgs(argv: readonly string[]): CliArgs {
  const args: CliArgs = {
    input: '.',
    format: 'text',
    failOn: 'none',
    compliance: [],
    help: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--help' || token === '-h') args.help = true;
    else if (token === '--input' || token === '-i') args.input = argv[++i] ?? '.';
    else if (token === '--format' || token === '-f') {
      const val = argv[++i] ?? 'text';
      if (val === 'text' || val === 'json' || val === 'sarif' || val === 'markdown') {
        args.format = val;
      } else {
        throw new Error(`Unsupported --format "${val}". Expected text|json|sarif|markdown.`);
      }
    } else if (token === '--fail-on') {
      const val = argv[++i] ?? 'none';
      if (val === 'none' || val === 'low' || val === 'medium' || val === 'high' || val === 'critical') {
        args.failOn = val;
      } else {
        throw new Error(`Unsupported --fail-on "${val}". Expected none|low|medium|high|critical.`);
      }
    } else if (token === '--compliance') {
      const raw = argv[++i] ?? '';
      args.compliance = raw
        .split(',')
        .map((s) => s.trim())
        .filter((s): s is ComplianceFramework => s === 'uae-pdpl' || s === 'desc-isr' || s === 'soc2');
    } else {
      throw new Error(`Unknown CLI option: ${token}`);
    }
  }
  return args;
}

function run(): void {
  const args = parseCliArgs(process.argv.slice(2));
  if (args.help) {
    console.log(
      'Usage: owasp-agentic-audit --input <path> [--format text|json|sarif|markdown] [--fail-on none|low|medium|high|critical] [--compliance uae-pdpl,desc-isr,soc2]',
    );
    return;
  }

  const summary = scanPath(args.input, { compliance: args.compliance });
  if (args.format === 'sarif') console.log(formatSarif(summary));
  else if (args.format === 'json') console.log(JSON.stringify(summary, null, 2));
  else if (args.format === 'markdown') console.log(formatMarkdown(summary, args.compliance));
  else console.log(formatText(summary));

  if (args.failOn !== 'none') {
    const threshold = SEVERITY_RANK[args.failOn];
    const breached = summary.findings.some((f) => SEVERITY_RANK[f.severity] >= threshold);
    if (breached) {
      process.exitCode = 1;
    }
  }
}

run();
