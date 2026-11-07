# YaCT logo

The logo combines the three ideas behind YaCT:

- **A padlock** – an encrypted vault.
- **The keyhole is a "Y"** – the initial of YaCT, at the place where the key fits.
- **A lattice in the background** – ML-KEM, YaCT's post-quantum algorithm, is
  lattice-based cryptography. The lattice is skewed, as lattice bases usually are.

Colours: tile gradient `#0B1D3A` → `#0E7480`, keyhole `#0C2547`, lock `#FFFFFF` → `#DCE9F2`.

| File | Use |
|---|---|
| `yact-logo.svg` | The logo; source for 48 px and larger |
| `yact-logo-small.svg` | Simplified drawing for 16–32 px: no lattice, larger lock, heavier Y |
| `yact-wordmark-light.svg`, `-dark.svg` | Logo with name, for light and dark backgrounds |
| `*.png` | Renderings of the above |
| `social-preview.png` | 1280 × 640 image for the GitHub repository preview |

Application icons are in `yact-ui/src/main/resources/yact/ui/icons/` (window
icons) and `packaging/icons/` (`.png` for Linux, `.ico` for Windows, `.icns` for
macOS).

The PNG, ICO and ICNS files were rendered from the SVG sources with Chromium
(through Playwright) and converted with ImageMagick and Pillow.

The GitHub social preview cannot be set through the API: upload
`social-preview.png` under *Settings → General → Social preview*.
