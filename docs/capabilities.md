# Adapter capability matrix

| Adapter | Detection | Parsing | Frameworks | Routes | Controls | Tracing/data flow | Dependencies |
|---|---|---|---|---|---|---|---|
| Go | extension | lexical | net/http imports; Gin, Fiber, Chi from `go.mod` | not implemented | narrow rules | not implemented | manifest inventory only |
| Python | extension | lexical | FastAPI, Django, Flask hints | not implemented | narrow rules | not implemented | manifest inventory only |
| Java | extension | lexical | Spring Boot hints | not implemented | narrow rules | not implemented | manifest inventory only |
| JS/TS | extension | lexical | Express, NestJS, React, Next.js from `package.json` | not implemented | narrow rules | not implemented | manifest inventory only |
| Terraform/YAML/JSON | extension | lexical | configuration inventory | n/a | narrow rules | not implemented | not implemented |

Framework discovery uses exact dependency names in recognized manifests, plus exact `net/http` Go imports. It is evidence that a dependency exists, not proof that a framework or security control is active. Unsupported files and files excluded by safety limits appear in the report when applicable.
