# Security

**English** · [简体中文](SECURITY.zh-CN.md)

OpenKeylet is a local credential execution tool exposed through stdio MCP. Its primary goal is to let an Agent complete authentication without placing hidden credential plaintext in ordinary MCP arguments or responses.

## Security goals

- Vault secrets are encrypted at rest with authenticated encryption.
- Modules that are not marked `agentVisible` do not return plaintext through `items_search`.
- Hidden values can be used locally by `credential_fill`, `ssh_run`, `ssh_upload`, `ssh_download`, and `http_send`.
- Known stored credentials are redacted from activity errors, terminal output, SSH output, and API responses where OpenKeylet can identify them.
- OpenKeylet-controlled authentication headers cannot be replaced by the caller; saved service URLs are defaults rather than authorization boundaries.

## Explicitly agent-visible values

The per-module **Agent visible** switch is a disclosure decision. When it is enabled, `items_search` includes that module's `value`, and the value may enter the Agent's context and its model provider's logs. For a visible TOTP module, OpenKeylet returns only the current six-digit code, never the permanent TOTP seed.

Do not enable Agent visibility for a value that must remain outside the Agent context. This switch is separate from whether the module may be used by OpenKeylet for fill, SSH, or API actions.

## What OpenKeylet does not protect against

OpenKeylet is not a sandbox, policy engine, DLP system, or authorization server. It does not defend against:

- a malicious or compromised Agent;
- another process running as the same operating-system user;
- a compromised browser, extension, terminal, remote host, or operating system;
- an Agent focusing the wrong desktop or browser control;
- sensitive data newly produced by a command or remote service;
- a task whose requested destination or operation is itself unsafe.

MCP tool annotations are descriptive hints. OpenKeylet enforces its actual restrictions in the Rust backend and never treats annotations or prompt instructions as authorization.

## Action boundaries

### Browser and desktop fill

The extension popup uses exact scheme, host and port unless an item has explicit website rules. Multiple-website rules support domain/host/exact/prefix/regex/never matching; ordinary rules retain the saved scheme and port, prefix rules also require the same origin, and regex matching refuses remote HTTP. Rules apply to the focused frame's URL, which is rechecked during injection. Different-origin frames are refused. The popup saves only after an explicit action. It shares the local vault rather than caching passwords in extension storage. A configured owner PIN also protects popup access; each passkey operation verifies it afresh. The bridge pins the extension origin during pairing and requires a pairing token for every WebSocket connection. Page content cannot choose vault RPC methods. Passkey requests use a separate extension-origin confirmation window, validate the RP ID against the page origin and public-suffix list, and set the UV flag only after successful PIN verification. Private keys never enter page scripts, extension storage, or Agent-readable fields. Local processes running as the same OS user remain outside this protection boundary.

Optional save suggestions sample visible login fields on a browser-generated form submission after trusted user interaction, not on each keystroke. This is a convenience heuristic, not evidence that a site is trustworthy or that authentication succeeded. Only HTTPS/local pages with the same origin as their top-level tab are eligible. Drafts are bounded to ten tabs and five minutes, held in service-worker memory, and never written to extension storage or sent to an external service. The source URL comes from Chrome's sender metadata. Cross-origin navigation, tab close, bridge disconnection, opt-out, dismissal and explicit extension locking discard drafts. Only a trusted extension page can read them after the configured PIN unlock or commit them with version checks; page messages cannot save or read credentials. The on-page notice carries no captured values. Existing-login comparisons occur locally only while unlocked. Browser/worker restart may discard an unsaved suggestion.

`credential_fill` writes one value to the currently focused control. When the caller sets `submit=true`, OpenKeylet also submits the focused browser form or presses Enter in a desktop or managed-terminal target. Desktop fill depends on the real operating-system foreground focus; background DOM focus is not sufficient. OpenKeylet cannot prove that the focused destination is trustworthy.

### Managed terminal

OpenKeylet remembers the most recently selected compatible project and the current managed terminal within each stdio MCP session. A unique `items_search` result or any explicit item selects the project, allowing later fill, SSH, transfer, HTTP, and terminal actions to omit the repeated name. `terminal_start`, or explicitly using another terminal ID, selects the current terminal so later write, read, fill, and stop calls can omit the repeated UUID. A PTY also keeps its own project binding until it ends. This is conversational convenience state, not an authorization boundary; ended terminals and disabled, deleted, or incompatible projects are ignored automatically.

OpenKeylet does not add a policy shell. `terminal_run` executes an ordinary one-shot local shell command, while `terminal_start` opens the requested program or native Windows script when an interactive process is needed. Children inherit OpenKeylet's normal user environment so installed tools behave as they do for the user. `terminal_run` can write caller-provided text directly to standard input, avoiding shell interpolation and temporary files. It and `terminal_start` can substitute `{{openkeylet:module}}` placeholders in commands or working directories; one-shot stdin, PTY arguments, and later `terminal_write` input support the same local substitution, and `secretEnv` can inject selected modules into a child environment. `terminal_write` may press Enter and `terminal_read` may wait for a requested marker without a OpenKeylet deadline unless the caller supplies one. Those values and common encodings are redacted from returned output. Local commands and ordinary terminal input may affect local or external systems. Redaction covers values filled or injected by OpenKeylet, not unrelated environment variables or every secret a process may print.

### SSH

An item with a saved password or private key can grant the Agent full SSH command execution and recursive SFTP file-or-directory transfer. Host, port, and username may be saved as defaults or supplied by the Agent for the current call; port 22 is used when neither source provides a port. `ssh_run` can write caller-provided text directly to the remote process's standard input and substitute `{{openkeylet:module}}` placeholders in that input, its command, or working directory. `secretEnv` can inject additional stored modules into the remote environment. OpenKeylet redacts those values from returned output. Upload and download paths are selected by the Agent for the user's task, and existing destinations are replaced by default after a complete temporary copy has been prepared, including file-to-directory and directory-to-file changes. OpenKeylet has no observation, diagnostic, restricted, or execution mode. It does not pin or compare SSH host fingerprints; using an SSH credential delegates selection of the runtime destination to the Agent.

### API requests

Any enabled item with a configured secret can be used as an HTTP request context. When an item stores a service URL, the caller may omit the request URL to use it, pass a relative path, or provide another absolute HTTP/HTTPS URL. Without a saved URL, the Agent supplies an absolute HTTP/HTTPS URL. The saved URL is a convenience, not an Origin allowlist: using an item for HTTP delegates selection of the request destination to the Agent.

For authentication schemes not covered by the built-in API credential or Basic combinations, placeholders such as `{{openkeylet:password}}` or `{{openkeylet:service token}}` resolve the named module directly and are substituted locally in URL, header, query, JSON/text body, or form values. `http_send.secretBindings` is only an optional alias map when the placeholder name differs from the module. The resolved value is added to response and activity redaction without being returned to the caller; TOTP bindings use the current code rather than the stored seed.

OpenKeylet follows HTTP/HTTPS redirects, including redirects to another Origin, until the service stops redirecting or the caller's optional timeout is reached. The caller may send ordinary headers, cookies, `Host`, or its own authorization values; only headers OpenKeylet injects for the saved credential remain controlled by OpenKeylet. Response headers and bodies are not classified by field name: only secret values already known to OpenKeylet are redacted, so new cookies, credentials, or other sensitive data returned by a service can enter Agent context. Activity records include the HTTP method, Origin, and path without the query string. Known stored secrets are redacted before the activity is saved.

`http_send` can upload local files or save a response to a local file when the caller supplies a path. OpenKeylet does not independently decide whether a user-requested local file is appropriate to send, which HTTP/HTTPS destination should receive it, or where an explicitly requested response should be stored. Existing response files are replaced by default; the caller can explicitly disable replacement.

## Local data and backups

The vault and master-key files remain in the current user's application-data directory. PIN protects GUI plaintext viewing and extension vault access, and verifies each passkey operation. It is not a separate encryption key and does not stop another process running as the same user.

New desktop and CLI (`--passphrase`) `.mvault` exports use a separate user password (≥12 characters), a random 128-bit salt, Argon2id (64 MiB, 3 iterations, 1 lane), and XChaCha20-Poly1305 with version-bound associated data. No password or unlock key is included in the file. An incorrect password does not modify the local vault. Legacy and non-passphrase CLI automatically unlocked packages still include their unlock material and must be protected like plaintext secrets. Both containers remain importable.

### Remote Browser Bridge & Headless Management

Browser Bridge binds only to `127.0.0.1` by default. Non-loopback binding (`OPENKEYLET_BRIDGE_BIND`) is refused unless explicitly enabled with `OPENKEYLET_BRIDGE_ALLOW_LAN=1`, and supports optional client IP/CIDR allowlists (`OPENKEYLET_BRIDGE_ALLOW_IPS`), configurable extension origins (`OPENKEYLET_BRIDGE_ALLOWED_ORIGINS`), connection metadata logging (without credential values), connected-client tracking, and pairing token rotation (`openkeylet browser reset`). Internal `/internal/*` endpoints reject non-local peers even in LAN mode.

The optional headless management server (`openkeylet admin serve`) is disabled by default, binds strictly to `127.0.0.1:39273` for SSH tunnel access (`ssh -L 39273:127.0.0.1:39273 user@server`), requires a fresh 256-bit Bearer token with rotation and revocation endpoints, hides secret plaintext by default, and requires Owner PIN verification for explicit reveals when a PIN is configured. See [docs/HEADLESS_AND_REMOTE.md](docs/HEADLESS_AND_REMOTE.md).

Card, identity and secure-note fields use the existing encrypted secret envelope and default to hidden from agents. These fields alone do not enable generic SSH/HTTP/agent-fill capabilities. Browser access requires an unlocked session and a user-selected operation. Autofill checks the current origin, allows only HTTPS or local development addresses, skips hidden fields and never submits forms.

Deleted items remain encrypted in the local trash until explicitly purged, and cannot be resolved by agent operations, autofill or passkey signing. The latest 20 previous passwords are encrypted inside each item's secret envelope; only unlocked owner history commands can return them. History values are also included in known-secret redaction. Trash restore/purge and history clearing require current revision tokens. Full exports and GitHub snapshots retain trash and history; deleting locally does not erase previous backups.

## Optional GitHub snapshots

GitHub backup uses a separate authenticated-encryption format, not the self-unlocking `.mvault` container. A random 256-bit recovery key encrypts the entire portable payload with XChaCha20-Poly1305 and version-specific associated data. Neither the recovery key nor the repository access token is uploaded. When binding a private GitHub repository from the desktop app, OpenKeylet enables **Strong Cloud Vault mode** together with the connection: all local vault secrets and `github-backup.json` are re-encrypted under a fresh random 256-bit DEK stored only in RAM while unlocked, wrapped on disk (`strong-key.json`) in two slots (Argon2id 64 MiB master passphrase ≥12 chars + `okv1_` recovery key), and the local `master.key` is wiped from disk and OS keyring. Background `stdio` MCP sessions access the RAM key only while the desktop app is unlocked via an authenticated loopback session broker; locking or quitting immediately wipes RAM keys and pauses MCP. Disconnecting atomically reverts the unlocked vault back to standard local-key mode. Serialized local secret buffers are zeroized after use.

Account checks inspect only owned `private: true` repositories (verifying the `openkeylet-vault` topic or `openkeylet.vault.json` envelope header without decrypting) to discover existing vault repositories automatically. When explicitly selected, local GitHub CLI authorization is read through a hidden, bounded subprocess with a timeout; the token is not returned to the renderer. Repository creation is limited to the authenticated user's account and always requests private visibility. Existing repositories are never renamed or made private automatically. First upload is an explicit setup option and uses the same encrypted snapshot and conflict checks as later uploads.

The client talks only to GitHub.com's API, refuses redirects, bounds response/snapshot sizes, and does not echo remote error bodies. It checks repository identity, default branch and private visibility before uploads and restores. Updates use the previously acknowledged blob SHA; conflicting or uncertain writes are never force-retried. These checks do not stop the repository owner from later making a repository public, deleting it, or changing it between API calls. Authentication protects snapshot contents, not availability or rollback: the current manual backup format does not provide cryptographic freshness guarantees against a malicious repository operator.

Recovery imports merge into the vault transactionally, without deleting or overwriting local items. Git history retains past ciphertext. Disconnecting does not erase remote backups, remove other clones, revoke the token, or rotate the recovery key. Anyone with the recovery key and any snapshot can decrypt that snapshot. A compromised local user account remains outside the security boundary. Keep the recovery key separately; OpenKeylet cannot reset it for a user who has lost every copy and connected device.

## Signed GitHub Releases updates

OpenKeylet checks for updates via the fixed GitHub Releases manifest URL (`https://github.com/omaekumiko2-create/OpenKeylet/releases/latest/download/latest.json`) with no custom server or third-party domain. Official release builds embed a 32-byte Ed25519 public key at compile time and require a valid Ed25519 signature over the domain-separated manifest payload (`openkeylet-update-v1\n<payload>`), exact byte size and SHA-256 verification of the downloaded archive, HTTPS GitHub Releases host allowlisting (including redirects), SemVer downgrade protection, safe archive path validation (blocking traversal and links), and macOS `codesign --verify --deep --strict` verification before replacing application files. Local builds without an embedded release public key never auto-install updates. Installing updates or changing update preferences requires an unlocked owner session when PIN lock is configured.

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub Security Advisories. Do not include real credentials, vault files, backups, master-key files, API responses, terminal output, or sensitive local paths.
