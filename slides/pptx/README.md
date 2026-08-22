# Rendered PowerPoint decks (KOSEN-KMITL branded)

`week01.pptx … week19.pptx` — presentable, **KOSEN-KMITL-branded** PowerPoint decks
generated from the Marp markdown in `../weekNN.md` (the source of truth).

## Brand
- **KMITL main:** orange `#E35205` (Pantone 166c) — official CI 2022
- **KOSEN:** blue `#017BC4` (from the KOSEN-KMITL logo)
- **Neutrals (KMITL secondary):** white `#FFFFFF`, grey `#666666`, black `#000000`
- Logo: `assets/logo-small.png` (KOSEN-KMITL official, downscaled for small file size)
- Dark premium theme; logo on every slide; section icons + cards; native PPTX tables/charts.

## Regenerate (after editing the `../weekNN.md` source)
```bash
cd slides/pptx
npm install pptxgenjs react-icons react react-dom sharp   # once
node build_all.js                                         # rebuilds all 19 .pptx
```
The decks open and are fully editable in PowerPoint. Edit content in the Marp
`.md` files and re-run, or tweak the generated `.pptx` directly for one-off slides.

> Total size is kept small (~3 MB for all 19) by embedding a palette-quantized logo.
