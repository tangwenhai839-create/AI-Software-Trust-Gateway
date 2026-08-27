export type ScanStatus =
  | 'queued'
  | 'ingesting'
  | 'scanning'
  | 'reasoning'
  | 'scoring'
  | 'reporting'
  | 'completed'
  | 'partial'
  | 'failed'
  | 'cancelled';

export type ScanStage =
  | 'init'
  | 'ingestion'
  | 'static_analysis'
  | 'dependency_analysis'
  | 'provenance_analysis'
  | 'ai_reasoning'
  | 'scoring'
  | 'report_generation'
  | 'finished';

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type RiskLevel = 'safe' | 'low' | 'medium' | 'high';

export interface ScoreData {
  scoring_version: string;
  safety_score: number;
  risk_score: number;
  risk_level: RiskLevel;
  confidence: number;
  coverage: number;
  components: Record<string, any>;
  caps_applied: string[];
}

export interface ScanSummary {
  scan_id: string;
  target_url: string;
  target_ref: string;
  resolved_commit_sha?: string;
  status: ScanStatus;
  stage: ScanStage;
  progress_pct: number;
  error_summary?: string;
  languages: string[];
  findings_count: number;
  dependencies_count: number;
  vulnerabilities_count: number;
  score?: ScoreData;
  ai_enabled: boolean;
  requested_at: string;
  started_at?: string;
  completed_at?: string;
}

export interface Evidence {
  id: string;
  kind: string;
  source: string;
  location: string;
  excerpt_redacted: string;
  sha256: string;
  attributes: Record<string, any>;
}

export interface Finding {
  id: string;
  fingerprint: string;
  scanner_name: string;
  category: string;
  title: string;
  severity: Severity;
  confidence: number;
  file_path: string;
  line_start: number;
  line_end: number;
  remediation: string;
  evidences: Evidence[];
  ai_assessment?: Record<string, any>;
  status: string;
}

export interface Vulnerability {
  id: string;
  advisory_id: string;
  aliases: string[];
  summary: string;
  details: string;
  cvss_score?: number;
  severity: Severity;
  fixed_versions: string[];
  source_url: string;
}

export interface Dependency {
  id: string;
  ecosystem: string;
  name: string;
  version: string;
  scope: string;
  manifest_path: string;
  vulnerabilities: Vulnerability[];
}

export interface CapabilityInfo {
  version: string;
  mode: string;
  platform: string;
  scanners: string[];
  scanner_status?: Record<string, string>;
  ai_providers: string[];
  supported_ecosystems: string[];
  dynamic_sandbox_available: boolean;
  sandbox_notice: string;
}

export interface ScanAnalysis {
  scan_id: string;
  purpose_profile: Record<string, any>;
  provenance: Record<string, any>;
  ai_analysis: Record<string, any>;
  scanner_runs: Array<Record<string, any>>;
  coverage: Record<string, number>;
  dynamic_analysis: Record<string, any>;
}
