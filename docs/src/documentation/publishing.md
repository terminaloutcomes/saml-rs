# Publishing

This repository publishes docs using GitHub Pages from the mdBook sources in the repository.

## Source of truth in this repository

- Book config: `docs/book.toml`
- Book content: `docs/src/`
- Pages workflow: `.github/workflows/docs_pages.yml`

## How publishing works

1. Changes are pushed to `main`.
2. The workflow in `.github/workflows/docs_pages.yml` runs.
3. `mdbook build docs` produces static files in `docs/book/`.
4. The workflow uploads and deploys `docs/book/` to GitHub Pages.

## One-time repository setting

In GitHub repository settings, configure Pages to use **GitHub Actions** as the source.

## Local verification before pushing

```bash
mdbook build docs
```

```bash
mdbook serve docs --open
```

This lets you validate the rendered docs before a Pages deployment.
