# cache-warden

> English | [日本語](./README-ja.md)

A warden that caches secrets securely and fast.

## Problem

Secrets (API tokens, DB passwords, SSH keys) need to be both safe and fast. The op CLI is secure but slow (0.5-1s per item); environment variables are fast but leak from memory. cache-warden provides a cache that is "fast, secure, and re-extends via biometric auth when the TTL expires."

## How it works

cache-warden's core is a secure cache for secret values:

1. Register a secret as `static` (a direct value) or `command` (an upstream command such as `op read ...`)
2. Manage the lifecycle with two-stage TTLs: a soft-TTL expiry re-extends via re-authentication (e.g. TouchID), a hard-TTL expiry zeroizes the value
3. Authenticate the requester by walking the process tree, and protect the value in memory (mlock / zeroize)

SSH key management (the former authsock-warden) is absorbed as one protocol adapter on top of this core (cache-warden succeeds authsock-warden).

## Install

Homebrew (macOS; ships a signed & notarized `.app`):

```bash
brew install --cask kawaz/tap/cache-warden
```

From source:

```bash
cargo build --release -p cache-warden-cli
```

## Documentation

- [DESIGN.md](./docs/DESIGN.md) — Current implementation (domain + architecture)
- [STRUCTURE.md](./docs/STRUCTURE.md) — Repository physical structure
- [ROADMAP.md](./docs/ROADMAP.md) — Future considerations
- [decisions/INDEX.md](./docs/decisions/INDEX.md) — Design decisions (DR) index

## License

MIT License, Yoshiaki Kawazu (@kawaz)
