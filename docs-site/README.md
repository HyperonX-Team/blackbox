# BLACKBOX Documentation Site

This is a static documentation site for BLACKBOX, designed to be deployed to GitHub Pages.

## Structure

```
docs-site/
├── index.html          # Main documentation page
└── (assets, if any)
```

## Deployment

The site is automatically deployed to GitHub Pages on every push to `main` via the workflow in `.github/workflows/pages.yml`.

## Local Preview

Open `docs-site/index.html` directly in a browser, or serve it:

```bash
# Python
cd docs-site && python -m http.server 8000

# Node
npx serve docs-site

# Rust
cargo install miniserve
miniserve docs-site
```

Then open http://localhost:8000

## Custom Domain

To use a custom domain:

1. Add a `CNAME` file to `docs-site/` with your domain:
   ```
   blackbox.example.com
   ```

2. Configure DNS:
   - For apex domain: ALIAS/ANAME to `<username>.github.io`
   - For subdomain: CNAME to `<username>.github.io`

3. Enable "Enforce HTTPS" in repository Settings → Pages

## Content

The single-page site covers:
- Installation (prebuilt, cargo, pip)
- 5-minute quickstart
- Core features
- Built-in examples
- Package inspection commands
- Trust & signing workflow
- Advanced v0.2 features (WASM, Rust, thin packages, composites, SBOM)
- Cache management
- GUI application
- Complete manifest reference