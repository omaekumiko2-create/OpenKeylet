# Privacy practices and permission justifications

Use the English text below in the developer dashboard. Reconcile the selections with the final shipped build; the policy and the dashboard must describe the same behavior.

## Single purpose

OpenKeylet lets the user manage and use credentials from their local OpenKeylet desktop vault while browsing: saving and filling logins, confirming passkey operations, and filling selected cards and identities. The desktop companion is required. All extension features support this local credential-management purpose, including explicitly requested credential actions from the desktop's agent integration.

## Permission justifications

### contextMenus

Adds two explicit user-triggered right-click actions: “Save to OpenKeylet” on user-selected text (such as a newly created API key) and “Scan 2FA QR” on an image element. Nothing is read unless the user clicks the menu item, and drafts stay in extension worker memory for at most 5 minutes until confirmed.

### scripting

Used to read a login form when the user chooses “Save login,” verify the actual target frame URL, fill a selected login/card/identity, and execute a desktop-initiated credential fill in the focused control. Functions are included in the extension package; no downloaded code is evaluated. Frame and origin checks apply to vault form workflows.

### storage

Stores the local bridge port, pairing token, connection status and the user's explicit save-suggestion preference. The background worker and extension pages are the only contexts allowed to access this storage. Passwords and pending login suggestions are not stored there.

### https://*/*

Users manage credentials for arbitrary HTTPS websites. Website permissions allow account matching, content-script focus tracking, opt-in login-save detection, the supported passkey bridge, and user-selected autofill. These features must work on sites chosen by the user, including before a toolbar click for passkey and save-suggestion flows. The extension does not collect browsing history for analytics or advertising.

### http://*/*

The existing desktop MCP credential-fill feature supports a user-selected focused field on HTTP intranet and local development pages. The extension also connects to the local authenticated bridge at 127.0.0.1. Password-vault form flows, automatic save suggestions and card/identity filling reject non-local HTTP; only the desktop-initiated generic focused-control action supports broader HTTP. This distinction is intentional and must remain visible in the product description and review instructions.

If generic HTTP filling is removed from the product, narrow this permission and the isolated content-script matches to loopback patterns; do not keep broad HTTP access for hypothetical future features.

### Removed and unnecessary permissions

`tabs` was removed. Host permissions already provide the matching tab URL needed by these features; querying tab IDs or creating the extension's confirmation windows does not require the broad `tabs` permission. No `history`, `cookies`, `debugger`, `webRequest`, `downloads` or `nativeMessaging` permission is requested.

## Remote code

Choose “No” for remote executable code for this build. JavaScript, CSS and HTML ship in the package. The loopback service exchanges credentials, operation results and a fixed vocabulary of data messages; it does not supply JavaScript or dynamically selected code to execute. Changing this architecture requires another review of this declaration.

## Data categories

The extension handles the following data. Disclose them conservatively in the dashboard where the current form asks about data collected/used. Local processing is still explained in the privacy policy; “not sent to the developer” is not the same statement as “not accessed.”

| Dashboard category | Relevant behavior |
| --- | --- |
| Personally identifiable information | Login names, names, email addresses, postal addresses and other identity fields selected by the owner. |
| Authentication information | Passwords, passkey identifiers/authentication results and local pairing credentials. Passkey private keys stay in the desktop vault. |
| Financial and payment information | Cards stored by the owner and explicitly filled card fields. |
| Web history | Current website/frame URLs used for matching and origin checks; no retained browsing-history database. |
| User activity | Focus and submit/sign-in/continue/Enter events needed for credential actions and optional save suggestions; not continuous keystroke-value logging. |
| Website content | Login form labels/fields and selected visible form values, only for disclosed credential features. |

The extension does not provide health, location-tracking or personal-communications features. Secure notes are free text chosen by the user, not a feature that extracts their email or medical records. Do not claim that arbitrary user-provided text can never contain those categories.

Certify the dashboard's Limited Use statements only if they remain true for the release: no sale of data, no unrelated use or transfer, and no use to determine creditworthiness or for lending. The privacy policy contains the Limited Use commitment.

## Distribution and external services

The developer receives no extension telemetry or hosted vault data. Websites receive values the user chooses to fill and confirmed WebAuthn responses. The user's local desktop app receives credential data. Optional GitHub encrypted backups are a desktop feature and must be disclosed separately from extension networking. Agent access is owner-configured through the desktop and does not imply every vault field is sent to an AI model.

## Official references

- [Privacy dashboard](https://developer.chrome.com/docs/webstore/cws-dashboard-privacy)
- [Privacy and minimum-permission policy](https://developer.chrome.com/docs/webstore/program-policies/policies)
- [Tabs permissions](https://developer.chrome.com/docs/extensions/reference/api/tabs#permissions)
- [Storage access levels](https://developer.chrome.com/docs/extensions/reference/api/storage)
