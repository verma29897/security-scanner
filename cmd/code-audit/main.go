package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/verma29897/security-scanner/internal/audit"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "scan" {
		fmt.Fprintln(os.Stderr, "usage: code-audit scan [flags] <repository-url>")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	out := fs.String("out", "codeaudit-report", "output path prefix")
	maxBytes := fs.Int64("max-bytes", 2<<20, "maximum bytes per file")
	timeout := fs.Duration("timeout", 2*time.Minute, "clone and scan timeout")
	envFile := fs.String("env-file", "", "AI settings file outside the scanned repository")
	aiProvider := fs.String("ai-provider", "", "optional provider: openai, anthropic, or openai-compatible")
	aiModel := fs.String("ai-model", "", "optional AI model override")
	aiBaseURL := fs.String("ai-base-url", "", "optional HTTPS endpoint for an OpenAI-compatible provider")
	allowAI := fs.Bool("allow-ai-external", false, "explicitly allow redacted finding metadata to be sent to the AI provider")
	_ = fs.Parse(os.Args[2:])
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "scan requires exactly one repository URL")
		os.Exit(2)
	}
	cfg := audit.DefaultConfig()
	cfg.MaxFileBytes = *maxBytes
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	report, err := audit.Scan(ctx, fs.Arg(0), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "code-audit: %v\n", err)
		os.Exit(1)
	}
	aiCfg, err := audit.LoadAIConfig(*envFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "code-audit: AI configuration: %v\n", err)
		os.Exit(1)
	}
	aiCfg, err = audit.OverrideAIConfig(aiCfg, *aiProvider, *aiModel, *aiBaseURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "code-audit: AI configuration: %v\n", err)
		os.Exit(1)
	}
	aiCfg.ExternalTransmission = aiCfg.ExternalTransmission || *allowAI
	audit.ApplyAIReview(ctx, &report, aiCfg)
	if err := audit.WriteReports(report, *out+".json", *out+".html"); err != nil {
		fmt.Fprintf(os.Stderr, "code-audit: write reports: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("scanned %s at %s: %d actionable findings, %d informational observations; reports: %s.json, %s.html\n", report.Repository.URL, report.Repository.CommitSHA, report.ActionableFindingCount(), len(report.Findings)-report.ActionableFindingCount(), *out, *out)
}
