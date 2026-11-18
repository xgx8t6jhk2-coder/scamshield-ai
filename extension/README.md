# ScamShield AI Guard · درع الاحتيال

## Load in Chrome or Edge

1. From the project root, run `node scripts/build-extension.mjs` to copy the shared detector into the extension. Run it again after any engine change. To regenerate the four icons, run `node scripts/generate-icons.mjs`.
2. Open `chrome://extensions` or `edge://extensions` and enable **Developer mode**.
3. Choose **Load unpacked**, select the `extension/` directory, and pin **ScamShield AI Guard** to the toolbar if desired.
4. After reloading the extension, refresh any already-open Gmail, Outlook Web or WhatsApp Web tabs to activate link highlighting.

The interface follows the browser's preferred language. Arabic uses a right-to-left layout. The interstitial displays the strongest available signals in both languages.

## What it does

- A dangerous web destination triggers an interstitial. Chrome and Edge may already have started loading the destination before the navigation event is handled. **Go back to safety** replaces the warning with a blank page. Choosing **continue** allows that exact hostname across tabs until the browser session ends or the extension reloads.
- A suspicious page shows an orange **!** badge. Open the toolbar popup for its score and signals.
- Right-click a link and choose **Check this link with ScamShield** to display its verdict in a separate extension window.
- In Gmail, Outlook Web and WhatsApp Web, dangerous links receive a dashed red outline and show an explanation on hover or keyboard focus.

## Permissions

| Permission | Purpose |
| --- | --- |
| `webNavigation` | Inspect top-frame navigation both when it starts and when it commits, including redirected destinations. |
| `tabs` | Read the active tab's URL when the toolbar popup opens. |
| `storage` | Keep temporary hostname exceptions in the browser's extension session storage. |
| `contextMenus` | Add the right-click command for links. |
| ScamShield API host access | Submit a report to the project's API after an explicit click. |
| Gmail, Outlook Web and WhatsApp Web content script matches | Inspect link URLs for hover warnings on the listed web apps. These same origins can load the packaged detector and its link-check module. |

## Privacy

Navigation and link analysis run entirely in the browser. Hover checks read anchor destinations locally. Reporting is optional and sends the engine's campaign fingerprint and the fixed channel value `extension` only when you click the report button. The fingerprint can include the registrable domain, score and signal IDs. It excludes full URL paths, query strings and message text. Opening the project link navigates to the website.
