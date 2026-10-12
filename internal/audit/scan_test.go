package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRepositoryURL(t *testing.T) {
	good := []string{"https://github.com/acme/repo.git", "git@github.com:acme/private.git"}
	for _, u := range good {
		if err := validateRepositoryURL(u, nil); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	bad := []string{"http://github.com/a/b", "https://user:token@github.com/a/b", "file:///tmp/x", "-upload-pack=evil", "https://127.0.0.1/x"}
	for _, u := range bad {
		if err := validateRepositoryURL(u, nil); err == nil {
			t.Errorf("accepted unsafe URL %s", u)
		}
	}
	if err := validateRepositoryURL("https://gitlab.com/a/b", []string{"github.com"}); err == nil {
		t.Fatal("accepted unapproved host")
	}
}

func TestScanRedactsSecretAndEscapesHTML(t *testing.T) {
	d := t.TempDir()
	source := "package main\nvar apiKey = \"supersecretvalue\" // <script>alert(1)</script>\n"
	if err := os.WriteFile(filepath.Join(d, "main.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := scanDirectory(context.Background(), d, Repository{URL: "test", CommitSHA: "abc"}, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("got %d findings", len(r.Findings))
	}
	if strings.Contains(r.Findings[0].Evidence, "supersecretvalue") {
		t.Fatal("secret was not redacted")
	}
	html := filepath.Join(d, "r.html")
	jsonPath := filepath.Join(d, "r.json")
	if err := WriteReports(r, jsonPath, html); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(html)
	if strings.Contains(string(b), "<script>alert") {
		t.Fatal("HTML evidence was not escaped")
	}
}

func TestSymlinkIsSkipped(t *testing.T) {
	d := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.go")
	_ = os.WriteFile(outside, []byte(`var password="notreadplease"`), 0600)
	if err := os.Symlink(outside, filepath.Join(d, "link.go")); err != nil {
		t.Skip(err)
	}
	r, err := scanDirectory(context.Background(), d, Repository{}, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 || len(r.Skipped) != 1 {
		t.Fatalf("findings=%d skipped=%d", len(r.Findings), len(r.Skipped))
	}
}

func TestStableFindingID(t *testing.T) {
	d := t.TempDir()
	_ = os.WriteFile(filepath.Join(d, "x.go"), []byte("package x\nvar token = \"abcdefghijk\"\n"), 0600)
	a, _ := scanDirectory(context.Background(), d, Repository{}, DefaultConfig())
	b, _ := scanDirectory(context.Background(), d, Repository{}, DefaultConfig())
	if a.Findings[0].ID != b.Findings[0].ID {
		t.Fatal("finding IDs differ")
	}
}

func TestReviewedFixtures(t *testing.T) {
	cfg := DefaultConfig()
	insecure, err := scanDirectory(context.Background(), filepath.Join("..", "..", "testdata", "insecure"), Repository{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(insecure.Findings) != 2 {
		t.Fatalf("insecure fixture: want 2 findings, got %d", len(insecure.Findings))
	}
	secure, err := scanDirectory(context.Background(), filepath.Join("..", "..", "testdata", "secure"), Repository{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(secure.Findings) != 0 {
		t.Fatalf("secure fixture: want 0 findings, got %d", len(secure.Findings))
	}
}

func TestTestCredentialIsNotCritical(t *testing.T) {
	d := t.TempDir()
	testDir := filepath.Join(d, "tests", "integration")
	if err := os.MkdirAll(testDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(testDir, "auth_test.go"), []byte("package integration\nvar token = \"a-token-of-sufficient-length\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := scanDirectory(context.Background(), d, Repository{}, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("got %d findings", len(r.Findings))
	}
	if got := r.Findings[0]; got.Severity != "informational" || got.Confidence != "low" || got.Context != "test_or_placeholder" {
		t.Fatalf("unexpected classification: %+v", got)
	}
}

func TestFrameworkDetectionUsesManifestsNotSubstrings(t *testing.T) {
	d := t.TempDir()
	goSource := "package server\n// react to the next express request\nimport \"net/http\"\nvar _ = http.MethodGet\n"
	if err := os.WriteFile(filepath.Join(d, "server.go"), []byte(goSource), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := scanDirectory(context.Background(), d, Repository{}, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.Frameworks, ",") != "net/http" {
		t.Fatalf("false framework detection: %v", r.Frameworks)
	}
	manifest := `{"dependencies":{"express":"^5.0.0","react":"^19.0.0"}}`
	if err := os.WriteFile(filepath.Join(d, "package.json"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	r, err = scanDirectory(context.Background(), d, Repository{}, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.Frameworks, ",") != "Express,React,net/http" {
		t.Fatalf("manifest detection failed: %v", r.Frameworks)
	}
}

func TestAIConfigFromSeparateEnvFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	contents := "CODEAUDIT_AI_MODE=external\nCODEAUDIT_AI_PROVIDER=anthropic\nCODEAUDIT_AI_MODEL=claude-test\nCODEAUDIT_AI_API_KEY=test-only-key\nUNRELATED_SECRET=ignored\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadAIConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Provider != "anthropic" || cfg.Model != "claude-test" || cfg.APIKey != "test-only-key" || !cfg.ExternalTransmission {
		t.Fatalf("unexpected config: provider=%q model=%q key-set=%v", cfg.Provider, cfg.Model, cfg.APIKey != "")
	}
	if _, err := aiEndpoint(AIConfig{Provider: "openai", BaseURL: "http://localhost:8080"}); err == nil {
		t.Fatal("accepted non-HTTPS AI endpoint")
	}
}

func TestAIDisabledAndConsentRequired(t *testing.T) {
	r := Report{}
	ApplyAIReview(context.Background(), &r, AIConfig{})
	if r.AIReview.Status != "disabled" {
		t.Fatalf("status=%q", r.AIReview.Status)
	}
	ApplyAIReview(context.Background(), &r, AIConfig{Provider: "openai", Model: "test", APIKey: "secret"})
	if r.AIReview.Status != "blocked" {
		t.Fatalf("status=%q", r.AIReview.Status)
	}
}
