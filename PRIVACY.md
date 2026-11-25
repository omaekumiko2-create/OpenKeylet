# OpenKeylet privacy policy

Last updated: October 20, 2026

This policy covers the OpenKeylet browser extension and its connection to the OpenKeylet desktop application. OpenKeylet is a local password and credential manager. It does not require an OpenKeylet account or operate a developer-hosted vault service.

## Information used

- Login names, passwords, website addresses and matching rules are used to find, save and fill the accounts you choose.
- Passkey account identifiers, relying-party information and cryptographic credentials are used for registration and sign-in. Private keys stay in the encrypted desktop vault; websites receive registration data or authentication signatures.
- Cards, identity information and secure notes are used for the vault features you select. Card and identity fields are sent to a website when you explicitly choose to fill them.
- The extension uses the current tab/frame address and focused control to match accounts, check the destination and carry out credential actions. It does not maintain a browsing-history database or send browsing activity to an analytics service.
- Extension settings, connection status, the local bridge port and a pairing token are stored in the browser's extension storage. Access is restricted to the extension's own pages and background worker.

## Optional save suggestions

Save suggestions are off until you enable them in the extension. When enabled, the extension reads visible login fields after form submission, relevant sign-in/continue button clicks, or Enter in a login field. These actions do not prove that sign-in succeeded. It does not record field values on every keystroke.

Username-only steps may be held in background memory for up to two minutes. Login suggestions, including passwords, remain in background memory for at most five minutes. They are not written to extension storage. Suggestions may be compared with your unlocked local vault to avoid duplicates. The extension writes a login to the vault only when you review and confirm it.

Disabling suggestions, explicitly locking from the extension, disconnecting the bridge, closing the relevant tab or navigating to another origin clears applicable temporary data. Browser/worker restarts also discard it. Manual “Save login” remains available without enabling automatic suggestions.

## Where information goes

The extension exchanges information with OpenKeylet on the same computer over an authenticated loopback connection. It does not send vault contents to an OpenKeylet server. Local loopback traffic is not TLS-encrypted; its protection relies on the local machine boundary, extension-origin validation and pairing token. This does not protect against a compromised operating-system user account.

When you fill a website, that website and scripts running on it can access the values you fill. Passkey operations send the website the data needed for registration or authentication after confirmation. The website's privacy practices then apply.

If you connect an AI agent through the desktop application's MCP integration, that agent can request enabled credential actions, including filling the focused browser control and, when explicitly requested by the action, submitting its form. Hidden plaintext is not returned to the agent by default; this is not a guarantee against a compromised destination, user-exposed fields or subsequent reads by other tools.

The desktop application has optional GitHub backup. If you configure and use it, encrypted snapshots and necessary repository/account metadata are transferred to GitHub. Snapshots include saved vault data, trash and password history. The key that decrypts them is stored in a second private repository of the same account, unless you supply your own key. Disconnecting does not remove existing remote snapshots or Git history. GitHub's own privacy policy applies to its service.

The desktop application also checks GitHub Releases (`releases/latest/download/latest.json`) for signed software updates when automatic update checks are enabled (configurable under **System → UPDATE / 07**). Update requests are read-only HTTPS GET requests carrying only a generic `OpenKeylet/<version>` User-Agent; no vault data, account information, or unique device identifiers are sent. You can disable automatic update checks or background downloads at any time.

OpenKeylet does not include advertising, sell personal data, or use vault data for profiling or model training. Data is used only for the disclosed credential-management features and their necessary operation, in accordance with the Chrome Web Store User Data Policy, including its Limited Use requirements.

## Storage, retention and deletion

Saved secrets are encrypted in the local desktop vault. A configured PIN controls owner access and passkey verification; it is not a separate vault-encryption key.

Deleted items remain in the local trash until you restore or permanently delete them. Up to 20 previous passwords per item are retained in encrypted history until cleared. Exported backups and optional GitHub snapshots can retain earlier copies after local deletion. You control these separate copies.

Removing the extension removes its browser-managed extension storage as handled by Chrome. It does not delete the desktop vault or backups. Use OpenKeylet's vault controls to remove items and history, and delete backups separately where stored. Generated passwords are not retained as generation history.

## Your choices

You can disable save suggestions, restrict extension site access in Chrome, lock the extension when a PIN is configured, disconnect Browser Bridge, decline a passkey request or choose the device/browser provider, and uninstall the extension. Restricting site access prevents related features on those sites. The extension needs the OpenKeylet desktop application to access the local vault.

## Contact and changes

Contact the OpenKeylet maintainers through [GitHub Issues](https://github.com/omaekumiko2-create/OpenKeylet/issues). For confidential security reports, use the repository's [private vulnerability reporting](https://github.com/omaekumiko2-create/OpenKeylet/security/advisories/new) if available; otherwise follow [SECURITY.md](SECURITY.md). Do not post credentials, vault files or personal data in public issues.

Material changes to data practices will be reflected in this policy and disclosed in the product when required. The date above identifies this version.
