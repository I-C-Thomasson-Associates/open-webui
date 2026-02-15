# Salas O'Brien Theme Icons

Place the following icon files in this directory to customize the Open WebUI icons when the Salas O'Brien theme is active.

| File | Size | Purpose |
|------|------|---------|
| `favicon.png` | 500×500 px | Main app icon (sidebar, profiles, notifications) |
| `favicon-dark.png` | 500×500 px | Dark mode variant of favicon |
| `favicon-96x96.png` | 96×96 px | High-res browser tab icon |
| `favicon.ico` | Standard .ico | Legacy browser tab icon |
| `favicon.svg` | SVG (scalable) | Vector browser tab icon |
| `logo.png` | 500×500 px | Logo display |
| `splash.png` | 500×500 px | Loading splash screen (light mode) |
| `splash-dark.png` | 500×500 px | Loading splash screen (dark mode) |
| `apple-touch-icon.png` | 180×180 px | iOS home screen icon |
| `web-app-manifest-192x192.png` | 192×192 px | PWA icon (small) |
| `web-app-manifest-512x512.png` | 512×512 px | PWA icon (large) |

**Notes:**
- All PNGs should be square with transparent backgrounds
- The favicon/logo is displayed as a circle in the UI (CSS `rounded-full`), so ensure the logo fits well within a circular crop
- The theme will gracefully fall back to default Open WebUI icons if any files are missing
- Brand colors: Impact Blue `#00A0E6`, Reflex Blue `#001489`
