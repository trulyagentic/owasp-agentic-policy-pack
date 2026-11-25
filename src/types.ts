export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type OwaspAsiId =
  | 'ASI01'
  | 'ASI02'
  | 'ASI03'
  | 'ASI04'
  | 'ASI05'
  | 'ASI06'
  | 'ASI07'
  | 'ASI08'
  | 'ASI09'
  | 'ASI10';

export type ComplianceFramework = 'uae-pdpl' | 'desc-isr' | 'soc2';

export interface ComplianceRef {
  readonly owaspName: string;
  readonly uaePdpl: readonly string[];
  readonly descIsrV3: readonly string[];
  readonly soc2Tsc: readonly string[];
}

export interface PolicyRuleMeta {
  readonly id: string;
  readonly owaspId: OwaspAsiId;
  readonly severity: Severity;
  readonly title: string;
  readonly description: string;
  readonly remediation: string;
}

export interface Finding {
  readonly ruleId: string;
  readonly owaspId: OwaspAsiId;
  readonly severity: Severity;
  readonly title: string;
  readonly message: string;
  readonly file: string;
  readonly line: number;
  readonly remediation: string;
  readonly compliance?: ComplianceRef;
}

export interface ScanSummary {
  readonly scannedFiles: number;
  readonly totalFindings: number;
  readonly bySeverity: Record<Severity, number>;
  readonly findings: readonly Finding[];
}

export interface ScanOptions {
  readonly compliance?: readonly ComplianceFramework[];
}
