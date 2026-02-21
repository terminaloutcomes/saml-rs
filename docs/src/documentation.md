# Documentation

The docs source and publish configuration live in this repository:

- Book config: `docs/book.toml`
- Book pages: `docs/src/`
- Publish workflow: `.github/workflows/docs_pages.yml`

## Local preview

Install mdBook, then run:

```bash
mdbook serve docs --open
```

## Build static site

```bash
mdbook build docs
```

The generated static site is written to `docs/book/`.

For deployment details, see [Publishing](documentation/publishing.md).
