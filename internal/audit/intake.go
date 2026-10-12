package audit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func validateRepositoryURL(raw string, allowed []string) error {
	if strings.ContainsAny(raw, "\x00\r\n") || strings.HasPrefix(raw, "-") {
		return errors.New("invalid repository URL")
	}
	host := ""
	if strings.HasPrefix(raw, "git@") {
		parts := strings.SplitN(strings.TrimPrefix(raw, "git@"), ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return errors.New("invalid SSH repository URL")
		}
		host = parts[0]
	} else {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
			return errors.New("repository URL must be HTTPS without embedded credentials, or git@host:path")
		}
		host = u.Hostname()
		if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
			return errors.New("repository host resolves to a prohibited address")
		}
	}
	if len(allowed) > 0 {
		ok := false
		for _, h := range allowed {
			if strings.EqualFold(host, h) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("repository host %q is not approved", host)
		}
	}
	return nil
}

func acquire(ctx context.Context, raw string, cfg Config) (string, Repository, func(), error) {
	if err := validateRepositoryURL(raw, cfg.AllowedHosts); err != nil {
		return "", Repository{}, func() {}, err
	}
	dir, err := os.MkdirTemp("", "codeaudit-")
	if err != nil {
		return "", Repository{}, func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	cmd := exec.CommandContext(ctx, "git", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never", "-c", "submodule.recurse=false", "clone", "--depth=1", "--no-tags", "--no-recurse-submodules", "--", raw, filepath.Join(dir, "repo"))
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", Repository{}, func() {}, fmt.Errorf("clone failed (check URL and configured credentials): %w: %s", err, strings.TrimSpace(string(out)))
	}
	repoDir := filepath.Join(dir, "repo")
	sha, err := gitOutput(ctx, repoDir, "rev-parse", "HEAD")
	if err != nil {
		cleanup()
		return "", Repository{}, func() {}, err
	}
	branch, _ := gitOutput(ctx, repoDir, "symbolic-ref", "--short", "HEAD")
	return repoDir, Repository{URL: raw, CommitSHA: sha, DefaultBranch: branch}, cleanup, nil
}

func gitOutput(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", args[0], err)
	}
	return strings.TrimSpace(string(out)), nil
}
