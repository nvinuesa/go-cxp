# AGENTS.md

This document defines the rules and expectations for all contributors and automated agents working on this project.

## 1. Testing Requirements

- **All code MUST be covered by unit tests.**
- New features, bug fixes, and refactors are not considered complete without corresponding tests.
- Tests should be:
  - Deterministic
  - Fast
  - Runnable offline
- Prefer table-driven tests where appropriate.
- Avoid mocking unless it meaningfully improves test clarity or isolation.

## 2. Dependency Policy (Go)

- **Minimize external dependencies.**
- Do **not** introduce a new Go dependency unless it is absolutely necessary.
- When a dependency is required:
  - Prefer small, well-audited, security-focused libraries
  - Avoid large frameworks or convenience wrappers
- Well-justified exceptions are allowed (e.g. Filippo Valsorda’s cryptographic libraries such as `piv`), but must be documented in code or PR description.
- Standard library solutions are always preferred when feasible.

## 3. CLI Design Guidelines

- The CLI must remain **simple, predictable, and script-friendly**.
- Follow **GNU-style flags**:
  - Long flags use `--` (e.g. `--config`, `--json`)
  - Short flags use `-` (e.g. `-v`, `-h`)
- Flags should be consistent across commands and avoid surprises.
- Output should be human-readable by default, with optional machine-readable formats (e.g. JSON).

## 4. CLI Command Structure

- The CLI should use **REST-like, resource-oriented commands**, inspired by tools such as `kubectl` and `juju`.
- Prefer verb-noun or noun-subcommand patterns, for example:
  - `cert issue`
  - `cert revoke`
  - `user list`
  - `ca status`
- Commands should be composable and intuitive, mirroring the underlying domain model.
- Avoid deeply nested or overly complex command trees.

## 5. HTTP API Requirements

- The project MUST expose a **RESTful HTTP API**.
- The API should support core functionality such as:
  - Certificate issuance
  - Certificate revocation
  - Status and health checks
- API design principles:
  - Clear, resource-oriented endpoints
  - Proper use of HTTP methods (`GET`, `POST`, `DELETE`, etc.)
  - Meaningful HTTP status codes
- The HTTP API should be usable independently of the CLI.
- Authentication, authorization, and transport security must be explicitly considered and documented.

## 6. Documentation Requirements

- All public APIs, including CLI and HTTP, must be documented.
- Documentation should be clear, concise, and easy to understand.
- Documentation should include examples and usage instructions.
- Documentation should be versioned and updated as the project evolves.

## 7. Version control
- The project MUST use a version control system such as Git.
- Version control should be used to track changes to the project.
- Version control should be used to manage releases and deployments.
- Version control should be used to manage branches and tags.
- Individual commits must follow the conventional commit format.

## 8. Generic LLM agents rules
- Never create summary files
- Be concise and precise with your responses

---

These rules exist to keep the project:
- Secure
- Auditable
- Maintainable
- Friendly to operators and automation

All contributions are expected to comply with this document.
