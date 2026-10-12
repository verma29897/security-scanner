package audit

import "time"

type Status string

const (
	Detected      Status = "detected"
	Partial       Status = "partial_or_weak"
	Missing       Status = "potentially_missing"
	Unknown       Status = "unknown"
	NotApplicable Status = "not_applicable"
)

type Config struct {
	AllowedHosts       []string
	MaxFileBytes       int64
	MaxFiles           int
	MaxRepositoryBytes int64
}

func DefaultConfig() Config {
	return Config{MaxFileBytes: 2 << 20, MaxFiles: 100000, MaxRepositoryBytes: 500 << 20}
}

type Repository struct {
	URL           string `json:"url"`
	CommitSHA     string `json:"commit_sha"`
	DefaultBranch string `json:"default_branch,omitempty"`
}
type Location struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}
type Finding struct {
	ID           string   `json:"id"`
	RuleID       string   `json:"rule_id"`
	RuleVersion  string   `json:"rule_version"`
	Category     string   `json:"category"`
	Status       Status   `json:"status"`
	Severity     string   `json:"severity"`
	Confidence   string   `json:"confidence"`
	Location     Location `json:"location"`
	Symbol       string   `json:"function_or_endpoint,omitempty"`
	Evidence     string   `json:"redacted_evidence"`
	Trace        []string `json:"trace,omitempty"`
	Rationale    string   `json:"rationale"`
	SuggestedFix string   `json:"suggested_fix"`
	Verification string   `json:"verification_steps"`
	Limitations  string   `json:"analysis_limitations,omitempty"`
	Origin       string   `json:"evidence_origin"`
	Context      string   `json:"context,omitempty"`
}
type Capability struct {
	Language           string `json:"language"`
	Parsing            string `json:"parsing"`
	FrameworkDetection string `json:"framework_detection"`
	RouteExtraction    string `json:"route_extraction"`
	ControlDetection   string `json:"control_detection"`
	ControlTracing     string `json:"control_tracing"`
	DataFlow           string `json:"data_flow_analysis"`
	DependencyAnalysis string `json:"dependency_analysis"`
	Limitations        string `json:"limitations"`
}
type SkippedFile struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}
type Control struct {
	Name     string     `json:"name"`
	Status   Status     `json:"status"`
	Evidence []Location `json:"evidence,omitempty"`
	Notes    string     `json:"notes,omitempty"`
}
type Provenance struct {
	Result         string `json:"result"`
	EvidenceSource string `json:"evidence_source,omitempty"`
	Trust          string `json:"trust,omitempty"`
	Limitations    string `json:"limitations"`
}
type AIReview struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider,omitempty"`
	Model    string `json:"model,omitempty"`
	Status   string `json:"status"`
	Summary  string `json:"summary,omitempty"`
	Error    string `json:"error,omitempty"`
	Notice   string `json:"notice"`
}
type Report struct {
	SchemaVersion string            `json:"schema_version"`
	Repository    Repository        `json:"repository"`
	ScannedAt     time.Time         `json:"scanned_at"`
	Scope         string            `json:"scope"`
	Languages     map[string]int    `json:"languages"`
	Frameworks    []string          `json:"frameworks"`
	Capabilities  []Capability      `json:"capabilities"`
	Controls      []Control         `json:"security_inventory"`
	Findings      []Finding         `json:"findings"`
	Skipped       []SkippedFile     `json:"skipped_files,omitempty"`
	Failures      []string          `json:"analysis_failures,omitempty"`
	Limitations   []string          `json:"limitations"`
	Provenance    Provenance        `json:"ai_assistance_provenance"`
	AIReview      AIReview          `json:"ai_review"`
	Engine        map[string]string `json:"engine"`
}

func (r Report) ActionableFindingCount() int {
	n := 0
	for _, finding := range r.Findings {
		if finding.Severity != "informational" {
			n++
		}
	}
	return n
}
