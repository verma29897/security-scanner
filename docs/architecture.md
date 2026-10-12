# Architecture and data flow

```text
URL -> intake validation -> isolated shallow Git clone -> immutable HEAD SHA
    -> bounded file inventory -> language/framework inventory -> versioned rules
    -> normalized evidence + redaction -> stable finding order -> JSON + escaped HTML
```

`cmd/code-audit` owns CLI parsing. `internal/audit/intake.go` validates and acquires repositories. `scan.go` owns inventory, narrow deterministic rules, normalization, and limitations. `model.go` is the report contract. `report.go` serializes reports.

Repository content is untrusted data. The scanner never executes repository code, tests, hooks, package managers, or build scripts. Git receives arguments without a shell; submodules and unnecessary protocols are disabled. Repository text is only evidence and never instructions. Every location uses a path relative to the cloned snapshot.

For hosted deployment, place an authorization layer before acquisition, allow-list provider hosts, isolate each job by tenant and OS identity/container, apply CPU/memory/time quotas, encrypt credentials and reports, and audit repository access. Those service components are not implemented in this milestone.
