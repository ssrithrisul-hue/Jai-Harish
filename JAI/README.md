# Digital Certificate Viewer

A small college mini-project: pick a digital certificate file (`.cer`, `.crt` or `.pem`)
and the page shows who it belongs to, who issued it, its serial number and how long
it is valid, plus a **Valid / Expired / Not yet valid** badge.

Everything is read **inside the browser**. No file is uploaded to any server, and there
is **no library or build step** — just plain HTML, CSS and JavaScript.

## How to run

1. Open the project folder `c:\Users\moort\OneDrive\Desktop\JAI`.
2. Double-click **`index.html`** (it opens in Chrome/Edge/Firefox). No server needed.
3. Choose a certificate file, then press **View Certificate**.

You can test it with any certificate file on your PC, for example:

* In Chrome: open a website, click the padlock → *Connection is secure* → *Certificate is valid* → *Details* → **Export**.
* Or export a `.cer` file from Windows: *certmgr.msc* → right-click a certificate → *All Tasks* → *Export*.

## Files

| File | What it does |
| --- | --- |
| `index.html` | Page structure: title, file picker, **View Certificate** button, results card. |
| `styles.css` | White-and-blue styling, responsive layout, status badge colours. |
| `certificate-parser.js` | Reads the certificate bytes (PEM or DER) and pulls out the details. |
| `app.js` | Connects the button to the parser and fills in the results area. |

## How it works (short version)

* A certificate is DER: `Tag | Length | Value` blocks nested inside each other.
  `certificate-parser.js` starts at the top-level `SEQUENCE` and walks down to the
  `serialNumber`, `issuer`, `validity` and `subject` fields.
* PEM files are the same bytes written in base64 between
  `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----`, so they are decoded first.
* Dates come as `UTCTime` (2-digit year: 50–99 → 19xx, 00–49 → 20xx) or `GeneralizedTime`.
* `app.js` compares `validFrom` / `validUntil` with today's date to decide the status
  and warns when the certificate expires within 30 days.

## Notes and limits

* Only the details listed above are shown; signatures are **not** verified and the
  certificate chain is not built, so "Valid" means "the dates are OK", not "trusted".
* The file name is checked as well as the contents, so `.txt`, `.p12`, `.pfx`,
  private keys and certificate signing requests produce a friendly error message.
