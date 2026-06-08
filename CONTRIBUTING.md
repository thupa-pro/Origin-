# Contributing

Thank you for considering contributing to Origin.

## Code of Conduct

This project follows the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct). By participating, you are expected to uphold it.

## What We Need Help With

| Area | Description |
|---|---|
| **Language bindings** | Python, Go, JS/TypeScript bindings for the core library |
| **Fuzz testing** | Add `cargo-fuzz` targets for the parser |
| **Documentation** | Examples, tutorials, integration guides |
| **Integration** | GitHub Action, Docker, Homebrew |
| **Bug fixes** | Open issues labeled "bug" |

## How to Contribute

### Reporting Bugs

Open a [GitHub Issue](https://github.com/thupa-pro/Origin/issues) with:
- A clear title
- Steps to reproduce
- Expected vs actual behavior
- Rust version and operating system

### Suggesting Features

Open a [GitHub Discussion](https://github.com/thupa-pro/Origin/discussions) first. Protocol changes must go through the RFC process.

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-change`
3. Make your changes
4. Run `cargo test` — all tests must pass
5. Run `cargo build --release` — no warnings
6. Commit with a clear message
7. Open a pull request

### Commit Messages

```
<area>: <brief description>

<optional detailed explanation>
```

Examples:
```
statement: fix base64url decoded-length check

The validator checked encoded length but not decoded byte count.
This allowed 44 chars → 33 bytes to pass.
```

### Code Style

- Follow existing patterns in the codebase
- No `unsafe` unless absolutely necessary and documented
- No `unwrap()` — use `?` or `expect()` with a message
- Keep functions small and focused
- Add tests for new functionality

### Protocol Changes

Any change to the statement format, canonical body, or verification algorithm requires:
1. An RFC document update
2. A new protocol version
3. Migration path for existing statements

## Development Setup

```bash
git clone https://github.com/thupa-pro/Origin.git
cd Origin
cargo test
cargo build --release
```

The core library is at `origin-core/`. The CLI is at `origin-cli/`.

## Questions

Open a [GitHub Discussion](https://github.com/thupa-pro/Origin/discussions) for questions.
