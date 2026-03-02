#!/usr/bin/env python3
import argparse
import json
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from scanner.cve_fetcher import CVEFetcher
from scanner.system_scanner import SystemScanner
from scanner.package_mapper import PackageMapper
from scanner.patch_checker import PatchChecker

console = Console()

def generate_table(findings):
    table = Table(title="Vulnerable Packages Detected", show_lines=True)
    table.add_column("Package", style="cyan", no_wrap=True)
    table.add_column("Installed Version", style="red")
    table.add_column("Fixed Version", style="green")
    table.add_column("USN ID", style="magenta")
    table.add_column("CVEs", style="yellow")
    
    for f in findings:
        cves_str = ", ".join(f['cves']) if f['cves'] else "N/A"
        table.add_row(
            f['package'],
            f['installed_version'],
            f['fixed_version'],
            f['usn_id'],
            cves_str
        )
    return table

def main():
    parser = argparse.ArgumentParser(description="Ubuntu Package Vulnerability Tracker & Patch Analyzer")
    parser.add_argument('--format', choices=['table', 'json'], default='table', help="Output format (default: table)")
    parser.add_argument('--limit', type=int, default=100, help="Number of recent USN notices to fetch (default: 100)")
    parser.add_argument('--fail-on-vuln', action='store_true', help="Exit with non-zero status if vulnerabilities are found (useful for CI)")
    
    args = parser.parse_args()
    
    if args.format == 'table':
        console.print(Panel("[bold yellow]Security Disclaimer:[/bold yellow] This tool performs standard read-only operations to detect vulnerabilities. It does not auto-patch your system or send sensitive data remotely.", title="Disclaimer"))
    
    try:
        if args.format == 'table':
             console.print("[*] Fetching vulnerability data...")
        fetcher = CVEFetcher()
        usn_data = fetcher.fetch_usn_data(limit=args.limit)
        
        if not usn_data:
            console.print("[red][!] Failed to fetch vulnerability definitions.[/red]")
            sys.exit(1)
            
        mapper = PackageMapper(usn_data)
        vulnerability_mapping = mapper.map_cves_to_packages()
        
        if args.format == 'table':
             console.print("[*] Scanning local system packages...")
        scanner = SystemScanner()
        installed_packages = scanner.get_installed_packages()
        
        if not installed_packages:
            console.print("[yellow][!] No installed packages detected. Are you running on Debian/Ubuntu/WSL?[/yellow]")
            sys.exit(0)
            
        if args.format == 'table':
             console.print("[*] Cross-referencing packages with CVEs...")
        checker = PatchChecker()
        findings = checker.check_system(installed_packages, vulnerability_mapping)
        
        if args.format == 'json':
            print(json.dumps(findings, indent=2))
        else:
            if not findings:
                console.print("\n[bold green]✅ No known vulnerabilities found for the analyzed packages![/bold green]")
            else:
                console.print(f"\n[bold red]⚠️ Found {len(findings)} vulnerable packages![/bold red]")
                console.print(generate_table(findings))
                
        if args.fail_on_vuln and findings:
            sys.exit(1)
            
    except Exception as e:
        console.print(f"[bold red][!] An error occurred during execution: {e}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
