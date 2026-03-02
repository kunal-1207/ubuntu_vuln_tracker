# Ubuntu Package Vulnerability Tracker & Patch Analyzer

A robust security tool that tracks Ubuntu package vulnerabilities (CVEs), maps them to installed packages, and assists in patch verification on Debian/Ubuntu systems.

## Features

- **Fetch CVEs:** Pulls CVE data directly from Ubuntu Security Notices (USN) JSON feeds and caches them locally to respect API limits.
- **Map CVEs → Packages:** Matches CVE datasets to specific Ubuntu/Debian package names and vulnerable versions.
- **Check Local System:** Detects installed package versions locally using `dpkg-query` natively.
- **Patch Status Verification:** Evaluates package versions against known vulnerable thresholds using native comparisons.
- **Security Reports:** Generates human-readable terminal tables (via `rich`) or strict JSON reports suitable for CI/CD environments.

## Architecture

- **`scanner/cve_fetcher.py`**: Fetches USN data and handles local caching.
- **`scanner/package_mapper.py`**: Refines large datasets into quick, checkable mappings.
- **`scanner/system_scanner.py`**: Uses native tools to build an inventory of local binaries.
- **`scanner/patch_checker.py`**: Handles logic for vulnerability intersections.
- **`cli.py`**: Primary interface integrating arguments, logic, and rendering.

## Important Security Disclaimers

⚠️ **Read-Only Operations:** This tool executes purely read-only commands (e.g., `dpkg-query`). It makes no attempt to modify system configurations, update applications, or auto-patch software.
⚠️ **No Remote Scanning:** System information remains fully localized. The tool never phones home or transmits installed package states to a remote API. API requests are outbound only to fetch standard security advisories.
⚠️ **Coordinated Disclosure:** Security findings must be verified before acting. Always validate through standard sysadmin processes (`apt update && apt upgrade` manually).

## Installation

```bash
git clone https://github.com/yourusername/ubuntu-vuln-tracker.git
cd ubuntu-vuln-tracker
pip install -r requirements.txt
```

## Usage

Run on an Ubuntu/Debian system or within a WSL environment:

```bash
# Pretty terminal output
python3 cli.py

# CI/CD integration using JSON and exit statuses
python3 cli.py --format json --fail-on-vuln
```
