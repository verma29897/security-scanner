package audit

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type rule struct {
	id, version, category, severity, confidence, rationale, fix, verify string
	pattern                                                             *regexp.Regexp
}

var rules = []rule{
	{"CA-GO-TLS-001", "1.0.0", "cryptography", "high", "high", "TLS certificate verification is explicitly disabled.", "Remove InsecureSkipVerify and configure a trusted CA or certificate pinning as appropriate.", "Run the TLS integration test with an untrusted certificate and confirm rejection.", regexp.MustCompile(`InsecureSkipVerify\s*:\s*true`)},
	{"CA-GO-CMD-001", "1.0.0", "command_injection", "high", "medium", "A shell interpreter appears to execute a dynamically constructed command.", "Avoid a shell; pass validated arguments directly to exec.Command.", "Test shell metacharacters as input and confirm they are treated as data.", regexp.MustCompile(`exec\.Command\s*\(\s*["'](?:sh|bash)["']\s*,\s*["']-c["']`)},
	{"CA-WEB-XSS-001", "1.0.0", "xss", "high", "medium", "HTML escaping is explicitly bypassed.", "Render untrusted content as text or sanitize it with a maintained allow-list sanitizer.", "Add a browser test using an HTML event-handler payload.", regexp.MustCompile(`dangerouslySetInnerHTML|\|\s*safe\b|Markup\s*\(`)},
	{"CA-DEBUG-001", "1.0.0", "configuration", "medium", "medium", "Debug mode appears enabled in source or configuration.", "Disable debug mode in production and set it through deployment configuration.", "Start the production configuration and confirm debug output is disabled.", regexp.MustCompile(`(?i)\b(debug\s*[:=]\s*true|FLASK_DEBUG\s*=\s*1)\b`)},
}

var secretAssignment = regexp.MustCompile(`(?i)(api[_-]?key|client[_-]?secret|secret|password|passwd|token)\s*[:=]\s*["']([^"']{8,})["']`)

var extensions = map[string]string{".go": "Go", ".py": "Python", ".java": "Java", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".tf": "Terraform", ".yaml": "YAML", ".yml": "YAML", ".json": "JSON"}

func Scan(ctx context.Context, raw string, cfg Config) (Report, error) {
	dir, repo, cleanup, err := acquire(ctx, raw, cfg)
	if err != nil {
		return Report{}, err
	}
	defer cleanup()
	return scanDirectory(ctx, dir, repo, cfg)
}

func scanDirectory(ctx context.Context, root string, repo Repository, cfg Config) (Report, error) {
	r := Report{SchemaVersion: "1.1.0", Repository: repo, ScannedAt: time.Now().UTC(), Scope: "default branch HEAD snapshot only; Git history and submodules excluded", Languages: map[string]int{}, Engine: map[string]string{"name": "CodeAudit", "version": "0.2.0", "ruleset": "2026.10.1"}, Provenance: Provenance{Result: "unknown", Limitations: "No trusted provenance record was found; authorship cannot be inferred from source style."}}
	r.Capabilities = capabilityMatrix()
	var total int64
	count := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			r.Failures = append(r.Failures, walkErr.Error())
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && (d.Name() == ".git" || d.Name() == "vendor" || d.Name() == "node_modules") {
				r.Skipped = append(r.Skipped, SkippedFile{rel, "vendored or repository metadata directory"})
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			r.Failures = append(r.Failures, rel+": "+err.Error())
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			r.Skipped = append(r.Skipped, SkippedFile{rel, "symbolic links are not followed"})
			return nil
		}
		count++
		total += info.Size()
		if count > cfg.MaxFiles || total > cfg.MaxRepositoryBytes {
			return fmt.Errorf("repository exceeds configured scan limits")
		}
		if info.Size() > cfg.MaxFileBytes {
			r.Skipped = append(r.Skipped, SkippedFile{rel, "file exceeds size limit"})
			return nil
		}
		lang, supported := extensions[strings.ToLower(filepath.Ext(rel))]
		if !supported {
			return nil
		}
		r.Languages[lang]++
		findings, binary, err := scanFile(path, rel)
		if err != nil {
			r.Failures = append(r.Failures, rel+": "+err.Error())
			return nil
		}
		if binary {
			r.Skipped = append(r.Skipped, SkippedFile{rel, "binary file"})
			return nil
		}
		r.Findings = append(r.Findings, findings...)
		detectFramework(rel, path, &r)
		return nil
	})
	if err != nil {
		return Report{}, err
	}
	sort.Slice(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Location.File == b.Location.File {
			if a.Location.StartLine == b.Location.StartLine {
				return a.RuleID < b.RuleID
			}
			return a.Location.StartLine < b.Location.StartLine
		}
		return a.Location.File < b.Location.File
	})
	r.Controls = buildControls(r.Findings)
	r.Limitations = []string{"Static, pattern-based rules do not prove exploitability or absence of controls.", "Interprocedural data-flow and route/control tracing are not implemented in this milestone.", "Dependency advisory lookup is not implemented; manifests are inventoried only.", "Unsupported files and dynamic behavior require manual review."}
	return r, nil
}

func scanFile(path, rel string) ([]Finding, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	probe := make([]byte, 8000)
	n, err := f.Read(probe)
	if err != nil && err != io.EOF {
		return nil, false, err
	}
	if strings.IndexByte(string(probe[:n]), 0) >= 0 {
		return nil, true, nil
	}
	if _, err = f.Seek(0, 0); err != nil {
		return nil, false, err
	}
	var out []Finding
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 2<<20)
	line := 0
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if match := secretAssignment.FindStringSubmatch(text); match != nil {
			out = append(out, secretFinding(rel, line, text, match[2]))
		}
		for _, ru := range rules {
			if ru.pattern.MatchString(text) {
				sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", rel, line, ru.id)))
				evidence := redact(text)
				out = append(out, Finding{ID: fmt.Sprintf("CA-%x", sum[:6]), RuleID: ru.id, RuleVersion: ru.version, Category: ru.category, Status: Partial, Severity: ru.severity, Confidence: ru.confidence, Location: Location{rel, line, line}, Evidence: evidence, Rationale: ru.rationale, SuggestedFix: ru.fix, Verification: ru.verify, Limitations: "Candidate identified by a deterministic narrow rule; validate surrounding control flow.", Origin: "deterministic_rule"})
			}
		}
	}
	return out, false, scanner.Err()
}

func secretFinding(rel string, line int, text, value string) Finding {
	severity, confidence, context := "critical", "high", "production_or_unknown"
	rationale := "A credential-like value is embedded in source."
	fix := "Remove the value, rotate the credential, and load it from a secret manager."
	verify := "Confirm the old credential is revoked and rescan."
	if isTestPath(rel) || looksLikePlaceholder(value) {
		severity, confidence, context = "informational", "low", "test_or_placeholder"
		rationale = "A credential-like value occurs in test or placeholder context; it is retained for review but is not evidence of a live credential."
		fix = "Confirm the value is synthetic and cannot authenticate to any real system. Keep test credentials scoped to test code."
		verify = "Search the value in credential stores and deployment configuration; document it as a fixture if synthetic."
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", rel, line, "CA-SECRET-001")))
	return Finding{ID: fmt.Sprintf("CA-%x", sum[:6]), RuleID: "CA-SECRET-001", RuleVersion: "1.1.0", Category: "secrets", Status: Partial, Severity: severity, Confidence: confidence, Location: Location{rel, line, line}, Evidence: redact(text), Rationale: rationale, SuggestedFix: fix, Verification: verify, Limitations: "A name/value heuristic cannot determine whether a credential is live; validate against the owning system.", Origin: "deterministic_rule", Context: context}
}

func isTestPath(rel string) bool {
	rel = strings.ToLower(filepath.ToSlash(rel))
	base := filepath.Base(rel)
	return strings.Contains("/"+rel, "/test/") || strings.Contains("/"+rel, "/tests/") || strings.Contains("/"+rel, "/testdata/") || strings.Contains("/"+rel, "/fixtures/") || strings.HasSuffix(base, "_test.go") || strings.HasSuffix(base, ".test.js") || strings.HasSuffix(base, ".test.ts") || strings.HasSuffix(base, ".spec.js") || strings.HasSuffix(base, ".spec.ts")
}

func looksLikePlaceholder(value string) bool {
	v := strings.ToLower(value)
	for _, marker := range []string{"test", "dummy", "example", "fixture", "fake", "mock", "placeholder", "changeme", "not-a-real", "sufficient-length"} {
		if strings.Contains(v, marker) {
			return true
		}
	}
	return false
}

var valueRedactor = regexp.MustCompile(`(?i)((?:api[_-]?key|secret|password|token)\s*[:=]\s*["'])[^"']+(["'])`)

func redact(s string) string {
	s = strings.TrimSpace(s)
	s = valueRedactor.ReplaceAllString(s, "${1}[REDACTED]${2}")
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

func detectFramework(rel, path string, r *Report) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	s, base := string(b), strings.ToLower(filepath.Base(rel))
	switch base {
	case "package.json":
		var manifest struct{ Dependencies, DevDependencies map[string]json.RawMessage }
		if json.Unmarshal(b, &manifest) == nil {
			deps := map[string]bool{}
			for k := range manifest.Dependencies {
				deps[k] = true
			}
			for k := range manifest.DevDependencies {
				deps[k] = true
			}
			for dep, name := range map[string]string{"express": "Express", "@nestjs/core": "NestJS", "next": "Next.js", "react": "React"} {
				if deps[dep] {
					addFramework(r, name)
				}
			}
		}
	case "go.mod":
		for module, name := range map[string]string{"github.com/gin-gonic/gin": "Gin", "github.com/gofiber/fiber": "Fiber", "github.com/gofiber/fiber/v2": "Fiber", "github.com/go-chi/chi": "Chi", "github.com/go-chi/chi/v5": "Chi"} {
			if hasGoModule(s, module) {
				addFramework(r, name)
			}
		}
	case "requirements.txt", "pyproject.toml", "pipfile", "poetry.lock":
		for dep, name := range map[string]string{"fastapi": "FastAPI", "django": "Django", "flask": "Flask"} {
			if hasPythonDependency(s, dep) {
				addFramework(r, name)
			}
		}
	case "pom.xml", "build.gradle", "build.gradle.kts":
		if strings.Contains(strings.ToLower(s), "spring-boot") {
			addFramework(r, "Spring Boot")
		}
	}
	if strings.HasSuffix(strings.ToLower(rel), ".go") && regexp.MustCompile(`(?m)^\s*(?:import\s+)?(?:_\s+)?["']net/http["']`).MatchString(s) {
		addFramework(r, "net/http")
	}
}

func addFramework(r *Report, name string) {
	for _, v := range r.Frameworks {
		if v == name {
			return
		}
	}
	r.Frameworks = append(r.Frameworks, name)
	sort.Strings(r.Frameworks)
}
func hasGoModule(s, module string) bool {
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(module) + `(?:\s|$)`)
	return re.MatchString(s)
}
func hasPythonDependency(s, dep string) bool {
	re := regexp.MustCompile(`(?im)^\s*` + regexp.QuoteMeta(dep) + `(?:\s|[=<>~!\[\]"]|$)`)
	return re.MatchString(s)
}

func buildControls(fs []Finding) []Control {
	controls := []Control{{"Authentication", Unknown, nil, "Route and middleware tracing is not implemented."}, {"Authorization", Unknown, nil, "Ownership and tenant checks require semantic analysis."}, {"Input validation", Unknown, nil, "Schema discovery is not implemented."}, {"Rate limiting", Unknown, nil, "Gateway configuration may be outside the repository."}}
	for _, f := range fs {
		if f.Category == "secrets" {
			controls = append(controls, Control{"Secret management", Partial, []Location{f.Location}, "Hard-coded credential candidate detected."})
			break
		}
	}
	return controls
}

func capabilityMatrix() []Capability {
	return []Capability{
		{Language: "Go", Parsing: "lexical", FrameworkDetection: "manifest/source heuristic", RouteExtraction: "not implemented", ControlDetection: "narrow deterministic rules", ControlTracing: "not implemented", DataFlow: "not implemented", DependencyAnalysis: "manifest inventory only", Limitations: "No AST or call graph yet."},
		{Language: "Python / Java / JavaScript / TypeScript", Parsing: "lexical", FrameworkDetection: "manifest/source heuristic", RouteExtraction: "not implemented", ControlDetection: "narrow deterministic rules", ControlTracing: "not implemented", DataFlow: "not implemented", DependencyAnalysis: "manifest inventory only", Limitations: "Initial inventory support; semantic adapters remain planned."},
	}
}
