# Privacy

## What the toolkit does

- **Scans files locally.** All scanning is performed on your local machine.
- **Does not upload code.** No source code is transmitted to external services.
- **Does not transmit credentials.** Detected secrets are redacted in all output formats.
- **No analytics or telemetry.** No usage data is collected.
- **No external API calls** during scanning (unless you explicitly enable an optional network-based check).

## What the toolkit does NOT do

- It does not send your code to any AI service.
- It does not upload scan results to any server.
- It does not make network requests during scanning.
- It does not follow symbolic links outside the scan root directory.
- It does not execute scanned PHP code or project scripts.

## Optional external tools

When the toolkit integrates with external tools (Composer, PHP, Semgrep), those
tools run locally. The toolkit does not pass your code to any external API.

Composer's audit feature may fetch advisory data from packagist.org. This is a
standard Composer operation and does not involve uploading your source code.
