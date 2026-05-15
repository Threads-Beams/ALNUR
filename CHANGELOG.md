# Changelog

All notable changes to ALNUR are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-05-15

### Added
- Multi-language project type detection (18 types)
- Dependency extraction from 15+ lockfile and manifest formats
- CVE scanning via OSV.dev batch API (npm, PyPI, Maven, NuGet, RubyGems, crates.io, Packagist, Go)
- Secret detection with 18 named patterns + Shannon entropy analysis
- 30+ architecture SAST rules across injection, crypto, TLS, and framework misconfigurations
- 15 software engineering standards compliance checks
- Port risk analysis for Dockerfiles, docker-compose, config files, and `.env`
- Console (Rich), JSON, and HTML report output
- `alnur scan` and `alnur detect` CLI commands
- CI/CD exit code support (exits 1 on critical/high findings)
