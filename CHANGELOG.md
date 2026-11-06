# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Entries are derived from Conventional Commits.

## [Unreleased]

### Added

- Add `verify`, `sign`, `presets` (GitHub, Standard Webhooks, Stripe style), `MemoryReplayStore` and `WebhookConfigError` for raw-body HMAC webhook verification with timestamp tolerance, replay protection and secret rotation.
- Initial project structure from the factory utility template.
