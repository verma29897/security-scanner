package audit

import (
	"encoding/json"
	"html/template"
	"os"
)

func WriteReports(r Report, jsonPath, htmlPath string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(jsonPath, append(b, '\n'), 0600); err != nil {
		return err
	}
	f, err := os.OpenFile(htmlPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return reportTemplate.Execute(f, r)
}

var reportTemplate = template.Must(template.New("report").Funcs(template.FuncMap{"json": func(v any) string { b, _ := json.Marshal(v); return string(b) }, "actionable": func(r Report) int { return r.ActionableFindingCount() }}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>CodeAudit report</title>
<style>body{font:15px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#18202a}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd4dc;padding:.55rem;text-align:left;vertical-align:top}th{background:#eef2f5}code{white-space:pre-wrap;overflow-wrap:anywhere}.high,.critical{color:#a21b16;font-weight:700}.meta{color:#52606d}.finding{border-left:4px solid #d04437;padding:0 1rem;margin:1.5rem 0}</style></head><body>
<h1>CodeAudit security review</h1><p class="meta">Repository: {{.Repository.URL}}<br>Commit: <code>{{.Repository.CommitSHA}}</code><br>Scanned: {{.ScannedAt}}<br>Scope: {{.Scope}}</p>
<h2>Summary</h2><p>{{actionable .}} actionable findings; {{len .Findings}} total observations. Test and placeholder credentials are retained as informational observations. Unknown controls are shown separately and are not counted as secure.</p>
<h2>Security inventory</h2><table><tr><th>Control</th><th>Status</th><th>Notes</th></tr>{{range .Controls}}<tr><td>{{.Name}}</td><td>{{.Status}}</td><td>{{.Notes}}</td></tr>{{end}}</table>
<h2>Findings</h2>{{range .Findings}}<section class="finding"><h3>{{.RuleID}} — <span class="{{.Severity}}">{{.Severity}}</span></h3><p><b>{{.Location.File}}:{{.Location.StartLine}}</b> · confidence {{.Confidence}} · {{.Status}}</p><code>{{.Evidence}}</code><p>{{.Rationale}}</p><p><b>Fix:</b> {{.SuggestedFix}}</p><p><b>Verify:</b> {{.Verification}}</p></section>{{else}}<p>No findings were produced. This does not prove the repository is secure.</p>{{end}}
<h2>Optional AI review</h2><p>Status: {{.AIReview.Status}}{{if .AIReview.Provider}} · Provider: {{.AIReview.Provider}} · Model: {{.AIReview.Model}}{{end}}</p>{{if .AIReview.Summary}}<p>{{.AIReview.Summary}}</p>{{end}}{{if .AIReview.Error}}<p>{{.AIReview.Error}}</p>{{end}}<p class="meta">{{.AIReview.Notice}}</p>
<h2>Languages</h2><pre>{{json .Languages}}</pre><h2>Frameworks</h2><pre>{{json .Frameworks}}</pre><h2>Limitations</h2><ul>{{range .Limitations}}<li>{{.}}</li>{{end}}</ul>
</body></html>`))
