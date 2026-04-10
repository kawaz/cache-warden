# cache-warden

Manage and protect cache socket paths.

## Problem

Unix domain sockets used by services (SSH Agent, GPG Agent, 1Password, Docker) are placed in volatile directories (`$TMPDIR`, `/tmp`, `$XDG_RUNTIME_DIR`) that change on reboot or between user sessions. Clients lose track of socket paths.

## How it works

cache-warden provides stable symlinks to volatile socket paths and manages their lifecycle:

1. Register a service's socket path
2. Create a stable symlink under `~/.cache-warden/sockets/`
3. Monitor socket health and update symlinks as needed
4. Clean up stale sockets

## Install

```bash
cargo build --release -p cache-warden-cli
```

## License

MIT
