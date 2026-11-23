# Instructions for Chrome Web Store reviewers

OpenKeylet is a companion to a local desktop vault. It has no OpenKeylet cloud account, subscription or reviewer login. Use synthetic credentials; never use a real password or payment card.

## Setup

1. Download the compatible desktop release from https://github.com/omaekumiko2-create/OpenKeylet/releases/latest. The publisher must confirm this release includes the features in the submitted extension before submission.
2. Run OpenKeylet on a supported desktop platform. Enable Browser Bridge in Settings. The default loopback port is 39272.
3. Install the submitted store extension. In the desktop Browser Bridge settings, use “Open Chrome & copy address” to start the pairing window, then open the extension. Do not also install the bundled development extension.
4. Confirm the extension shows CONNECTED. If the port was changed, enter it in the extension's Connection section. If pairing fails, the publisher must check that the desktop's allowed extension Origin matches the submitted store ID.
5. For PIN tests, configure a six-digit owner PIN in this isolated desktop vault. Otherwise owner vault features are available without a PIN. No special production access is needed.

## Password workflow

1. Use a controlled HTTPS sign-in page or a local development page with standard `autocomplete="username"` and `autocomplete="current-password"` fields.
2. Enter a synthetic account. Open the extension, choose “Save login,” inspect the source and values, and confirm. This writes only to the local desktop vault.
3. Clear the form and select the matching login in the popup. The fields fill; normal popup autofill does not submit the form.
4. Change the account from the desktop and reopen the popup to verify both use the same vault.
5. Open a browser management page. The popup should explain that these pages cannot be filled, while full vault management remains accessible.

## Optional save suggestions and privacy

1. In a fresh installation, leave “Enable save suggestions” unchecked. Submitting login fields should produce no save suggestion.
2. Read the disclosure and enable the checkbox. Submit a synthetic login or click a supported sign-in button.
3. Review the suggestion from the popup or page notice. Confirm that saving requires an explicit action; dismissing does not save.
4. Turn the option off, change origin, close the tab, disconnect the bridge or explicitly lock the extension. Applicable temporary suggestions are cleared. Drafts expire within five minutes; username-only steps within two minutes.
5. Open the bundled Privacy page from the popup footer.

## Cards, identities and notes

Create synthetic items in “Cards, identities & notes” or “All vault items.” On a controlled HTTPS page with standard autocomplete fields, explicitly choose a card or identity to fill. Hidden fields and cross-origin frames are not filled. Secure notes are vault items, not automatically injected into webpages. Delete an item, view Trash and restore it.

## Passkeys

Use a WebAuthn test website you control on top-level HTTPS (or localhost). Request ES256 registration with a discoverable credential. Confirm the origin/account in OpenKeylet's dedicated window and enter the owner PIN when user verification is requested. Test sign-in, cancellation and “Use device.” Private keys remain in the local desktop backend.

Conditional autofill, cross-origin frames, hardware attestation and unsupported extensions use the native provider where supported. This extension does not claim to replace all browser WebAuthn behavior.

## Desktop agent integration

The desktop's owner-configured MCP interface can send an authenticated, fixed-shape credential fill request to the extension. It writes into the current focused control; an explicit `submit` request can submit its form. This is separate from the popup's form-aware vault autofill. It supports HTTP intranet pages as well as HTTPS. It does not send executable JavaScript to the extension.

## Reproducing the automated checks

The source repository contains `scripts/test-browser.mjs`, `scripts/test-login-capture.mjs` and `src-tauri/examples/browser_fixture.rs`. They create an isolated synthetic vault and browser profile. The fixture PIN `123456` is test-only, not a password for any user account.

The attached store screenshots are captured from this isolated extension/backend setup. A synthetic website is clearly identified in the screenshots. No screenshot uses a real user vault or promises a feature absent from the extension.
