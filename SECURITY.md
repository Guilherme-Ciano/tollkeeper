# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | yes |
| < 1.0 | no |

Only the latest minor release receives security fixes.

## Reporting a vulnerability

Report privately at <https://github.com/Guilherme-Ciano/tollkeeper/security/advisories/new> (GitHub Private Vulnerability Reporting). Please do not open a public issue.

| Step | Target |
| --- | --- |
| Acknowledgement | 72 hours |
| Initial assessment and severity | 7 days |
| Fix for critical and high severity | 30 days |
| Coordinated disclosure | 90 days at most, earlier once a fix ships |

Fixed vulnerabilities are published as [GitHub Security Advisories](https://github.com/Guilherme-Ciano/tollkeeper/security/advisories) with a CVE when one applies, and noted in the release changelog.

## In scope

- Policy or rate-limit bypass (including parser differentials and header/body mismatches)
- Token passthrough or any path where a downstream credential reaches an upstream
- Audit chain forgery that `tollkeeper audit verify` does not detect
- Leakage of gateway secrets to stdio upstreams
- Denial of service with small inputs

The dev issuer (`tollkeeper dev-issuer`) is intentionally insecure and out of scope.
