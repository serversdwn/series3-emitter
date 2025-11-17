# Changelog
All notable changes to **Series3 Emitter** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),  
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [1.0.0] – 2025-09-02

### Added
- **Automatic roster refresh** from Dropbox at a configurable interval (`ROSTER_REFRESH_MIN_SECONDS`).
- **Hot-reload** of roster file without restarting the script.
- **Failsafe reload:** if the new roster is missing or invalid, the previous good roster is retained.
- **Atomic roster downloads** (temp file → replace) to avoid partial/corrupted CSVs.
- **Startup config echo** printing WATCH_PATH, ROSTER_FILE, and ROSTER_URL visibility.
- **Active / Bench / Ignored** unit categories for clearer fleet status mapping.

### Fixed
- Removed stray `note=note_suffix` bug in the “Unexpected Units” section.
- Removed duplicate `import time`.
- Removed duplicate roster load during startup (roster now loads once).
- Cleaned indentation for Python 3.8 compatibility.

### Changed
- Reset versioning from legacy `v5.9 beta` → **v1.0.0** (clean semver baseline).
- Main script normalized as `series3_emitter.py`.

---

[Unreleased]: https://example.com/compare/v1.0.0...HEAD  
[1.0.0]: https://example.com/releases/v1.0.0