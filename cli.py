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
    table = Table(title="🔍 Vulnerable Packages Detected", show_lines=True, header_style="bold magenta")
    table.add_column("Package", style="cyan", no_wrap=True)
    table.add_column("Installed Version", style="bold red")
    table.add_column("Fixed Version", style="bold green")
    table.add_column("USN ID", style="magenta")
    table.add_column("CVEs", style="yellow")
    
    for f in findings:
        cves_str = ", ".join(f['cves']) if f.get('cves') else "N/A"
        table.add_row(
            f['package'],
            f['installed_version'],
            f['fixed_version'],
            f['usn_id'],
            cves_str
        )
    return table

def main():
    parser = argparse.ArgumentParser(description="🛡️ Ubuntu Package Vulnerability Tracker & Patch Analyzer")
    parser.add_argument('--format', choices=['table', 'json'], default='table', help="Output format (default: table)")
    parser.add_argument('--limit', type=int, default=100, help="Number of recent USN notices to fetch (default: 100)")
    parser.add_argument('--fail-on-vuln', action='store_true', help="Exit with non-zero status if vulnerabilities are found (useful for CI)")
    parser.add_argument('--mock', action='store_true', help="Use mock data for demonstration (useful on Windows/Mac)")
    parser.add_argument('--input-file', type=str, help="Scan a package list from a file (format: 'name version')")
    parser.add_argument('--release', type=str, help="Specify the Ubuntu release (e.g., focal, jammy) to filter results")
    
    args = parser.parse_args()
    
    if args.format == 'table':
        console.print(Panel.fit(
            "[bold yellow]Security Disclaimer:[/bold yellow]\nThis tool performs standard read-only operations to detect vulnerabilities.\nIt does *not* auto-patch your system or send sensitive data remotely.",
            title="🛡️ Security Checker", border_style="blue"
        ))
    
    try:
        if args.format == 'table':
            msg = "[*] Fetching vulnerability data..." if not args.mock else "[*] [MOCK MODE] Fetching vulnerability data..."
            console.print(f"{msg} (limit: {args.limit})", style="dim")
        fetcher = CVEFetcher()
        usn_data = fetcher.fetch_usn_data(limit=args.limit)
        
        if not usn_data:
            console.print("[bold red][!] Failed to fetch vulnerability definitions.[/bold red]")
            sys.exit(1)
            
        mapper = PackageMapper(usn_data)
        vulnerability_mapping = mapper.map_cves_to_packages()
        
        if args.format == 'table':
             console.print("[*] Scanning system packages...", style="dim")
        scanner = SystemScanner()
        
        # Determine the release
        release = args.release
        if not release:
             release = scanner.get_os_release() if not args.mock else "jammy"
             
        if args.format == 'table':
            source_msg = f"from [cyan]{args.input_file}[/cyan]" if args.input_file else ("in [yellow]MOCK MODE[/yellow]" if args.mock else "locally")
            console.print(f"[*] Scanning packages {source_msg} (Release: [bold cyan]{release}[/bold cyan])...", style="dim")
            
        if args.input_file:
            installed_packages = scanner.load_from_file(args.input_file)
        else:
            installed_packages = scanner.get_installed_packages(mock=args.mock)
        
        if not installed_packages:
            if args.format == 'table':
                console.print("[bold yellow][!] No installed packages detected.[/bold yellow]")
                if not args.input_file:
                    console.print("[dim]Note: This tool requires 'dpkg-query'. It is intended for Debian/Ubuntu or WSL.[/dim]")
            sys.exit(0)
            
        if args.format == 'table':
             console.print("[*] Cross-referencing packages with CVEs...", style="dim")
        checker = PatchChecker()
        findings = checker.check_system(installed_packages, vulnerability_mapping, release=release)
        
        if args.format == 'json':
            print(json.dumps(findings, indent=2))
        else:
            if not findings:
                console.print(Panel(
                    "\n[bold green]✅ No known vulnerabilities found for the analyzed packages![/bold green]\n",
                    border_style="green"
                ))
            else:
                console.print(f"\n[bold red]⚠️ Found {len(findings)} vulnerable packages![/bold red]")
                console.print(generate_table(findings))
                
        if args.fail_on_vuln and findings:
            sys.exit(1)
            
    except Exception as e:
        console.print(f"[bold red][!] An error occurred: {e}[/bold red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
