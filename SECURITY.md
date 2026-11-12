# Security policy

## Supported versions

Only the latest minor release receives security fixes.

## Reporting a vulnerability

Use GitHub Private Vulnerability Reporting on this repository. Please do not open a public issue.

- Acknowledgement within 72 hours.
- Coordinated disclosure within 90 days, earlier if a fix ships.

## In scope

- Policy or rate-limit bypass (including parser differentials and header/body mismatches)
- Token passthrough or any path where a downstream credential reaches an upstream
- Audit chain forgery that `tollkeeper audit verify` does not detect
- Leakage of gateway secrets to stdio upstreams
- Denial of service with small inputs

The dev issuer (`tollkeeper dev-issuer`) is intentionally insecure and out of scope.
