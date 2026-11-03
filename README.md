# Hardcover for KOReader

A KOReader plugin for browsing Hardcover lists and series, attaching local book files, and mirroring them into KOReader collections.

## Install

Place this repository's plugin files in a directory named `hardcover.koplugin` inside KOReader's `plugins` directory. For example:

```text
koreader/
└── plugins/
    └── hardcover.koplugin/
        ├── _meta.lua
        └── main.lua
```

Restart KOReader, then open **Tools → More tools → Hardcover → Set access token**. The plugin stores the token in KOReader's settings directory; do not commit that settings file or paste tokens into source files.

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
