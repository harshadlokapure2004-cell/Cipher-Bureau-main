# Cipher Bureau — Classical Cryptography Casebook

A single-page, client-side toolkit for encoding and decoding text with
classical (pre-computer) ciphers — Caesar, Monoalphabetic, Playfair, Hill,
Vigenère, One-Time Pad, Rail Fence, and Columnar Transposition. Everything
runs in the browser; no server, build step, or dependencies beyond two
Google Fonts.

## Files

| File         | Purpose                                                                 |
|--------------|--------------------------------------------------------------------------|
| `index.html` | Page markup — header/nav, hero, toolkit, file tools, algorithm notes, security panel, footer, and the access-code gate. |
| `style.css`  | All styling — dark "cipher noir" theme (charcoal background, gold/brass and teal accents), layout, and responsive rules. |
| `script.js`  | All behavior — cipher implementations, UI wiring, drag-and-drop file encode/decode, the scrambling hero text effect, the animated cipher disc, and the local access-code gate. |

## Running it

No build tools needed. Either:

1. **Double-click `index.html`** to open it directly in a browser, or
2. **Serve it locally** (recommended, since some browsers restrict local
   file access for scripts):
   ```bash
   npx serve .
   # or
   python3 -m http.server 8000
   ```
   Then visit `http://localhost:8000`.

Keep all three files (`index.html`, `style.css`, `script.js`) in the same
folder — `index.html` references the other two by relative path.

## Notes

- **Access code / lock screen**: on first load you can optionally set a
  local access code that gates the toolkit on that device. This is stored
  only in the browser's local storage (or the artifact's persistent
  storage, if running inside one) — it is a UI convenience, **not**
  real security. The hash is SHA-256; there is no server-side check.
- **Everything is local**: text, files, and keys you enter never leave
  the browser — all cipher operations run client-side in `script.js`.
- **Not for real secrets**: these are educational/classical ciphers
  (Caesar, Vigenère, etc.), not cryptographically secure algorithms.
  Don't use this to protect anything sensitive.
- **Fonts**: `index.html` loads *Fraunces* (display serif) and
  *JetBrains Mono* (monospace) from Google Fonts via `<link>` tags in
  the `<head>`. An internet connection is needed for these to load;
  the page falls back to system serif/monospace fonts otherwise.

## Customizing the theme

All colors are defined as CSS custom properties at the top of
`style.css`:

```css
:root{
  --bg: ...          /* page background */
  --surface: ...      /* card/panel background */
  --border: ...        /* card/input borders */
  --ink: ...            /* primary text */
  --ink-dim: ...         /* secondary text */
  --ink-faint: ...        /* tertiary/placeholder text */
  --brass / --brass-bright: ...  /* primary accent (gold) */
  --teal / --teal-dim: ...        /* secondary accent (blue) */
  --rust: ...                      /* error/danger accent */
  --sage: ...                       /* success accent */
}
```

Changing these values restyles the entire site consistently, since the
rest of `style.css` references them rather than hardcoded colors.
