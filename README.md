# Hardcover for KOReader

A KOReader plugin for browsing Hardcover lists and series, attaching local book files, and mirroring them into KOReader collections.

[![Lua syntax check](https://github.com/gkgsiva/hardcover/actions/workflows/test.yml/badge.svg)](https://github.com/gkgsiva/hardcover/actions/workflows/test.yml)
[![Latest release](https://img.shields.io/github/v/release/gkgsiva/hardcover)](https://github.com/gkgsiva/hardcover/releases/latest)

## Install

1. Download the latest `hardcover.koplugin-<version>.zip` from the [GitHub Releases](https://github.com/gkgsiva/hardcover/releases) page.
2. Extract the archive. It contains a `hardcover.koplugin` folder.
3. Copy that folder into KOReader's `plugins` directory:

```text
koreader/
└── plugins/
    └── hardcover.koplugin/
        ├── _meta.lua
        └── main.lua
```

Common `plugins` directory locations:

- **Kindle**: `/mnt/us/koreader/plugins/`
- **Kobo**: `/mnt/onboard/.adds/koreader/plugins/`
- **Android**: `/sdcard/koreader/plugins/`

Restart KOReader, then open **Tools → More tools → Hardcover → Set access token**. The plugin stores the token in KOReader's settings directory; do not commit that settings file or paste tokens into source files.

### Install from a source checkout

The repository itself is also a KOReader plugin. Clone it directly to a directory ending in `.koplugin`:

```sh
git clone https://github.com/gkgsiva/hardcover.git /path/to/koreader/plugins/hardcover.koplugin
```

Restart KOReader after installing or updating the plugin.

## Features

- Browse and search Hardcover lists and series trackers.
- Attach local files to Hardcover books and open attached books in KOReader.
- Create and preview updates to KOReader collections.
- Search a selected folder for likely local matches and review editions before attaching.
- Filter books by local reading status and find replacements for missing attachments.
- Compare KOReader and Hardcover reading progress, select changes per book, and confirm before syncing.
- View cache freshness, pending collection changes, and sync diagnostics.
- Export and merge plugin-data backups. Backups exclude the access token.

Progress synchronization only applies to existing Hardcover reading records. When syncing progress to KOReader, the resume position is estimated by percentage.

## Releases

To publish a release, push a version tag such as `v1.0.0`. GitHub Actions builds a `hardcover.koplugin-v1.0.0.zip` archive and attaches it to the GitHub release.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for the SPDX identifier and link to the canonical license text.
