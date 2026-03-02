import subprocess
from typing import Dict, List, Any

class PatchChecker:
    def __init__(self):
        pass
        
    # Note: Proper dpkg version comparison requires `dpkg --compare-versions`
    def compare_versions(self, installed_ver: str, fixed_ver: str) -> bool:
        """
        Returns True if installed_ver is less than fixed_ver (i.e. vulnerable).
        """
        try:
            # dpkg --compare-versions 1.0 lt 2.0 -> returns 0 if true
            result = subprocess.run(
                ["dpkg", "--compare-versions", installed_ver, "lt", fixed_ver],
                capture_output=True, check=False
            )
            return result.returncode == 0
        except FileNotFoundError:
            # Fallback for non-Debian systems (very basic/naive string compare for demo)
            return installed_ver < fixed_ver

    def check_system(self, installed_packages: Dict[str, str], vulnerability_mapping: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """
        Cross-references installed packages against the vulnerability mapping.
        """
        findings: List[Dict[str, Any]] = []
        
        for pkg_name, installed_version in installed_packages.items():
            if pkg_name in vulnerability_mapping:
                vulns = vulnerability_mapping[pkg_name]
                for vuln in vulns:
                    fixed_version = vuln['fixed_version']
                    usn_id = vuln['usn_id']
                    
                    # If installed version is less than the fixed version, it's vulnerable
                    if self.compare_versions(installed_version, fixed_version):
                        findings.append({
                            "package": pkg_name,
                            "installed_version": installed_version,
                            "fixed_version": fixed_version,
                            "usn_id": usn_id,
                            "cves": vuln['cves'],
                            "release": vuln['release']
                        })
                        
        return findings

if __name__ == "__main__":
    try:
        from scanner.system_scanner import SystemScanner
        from scanner.cve_fetcher import CVEFetcher
        from scanner.package_mapper import PackageMapper
    except ImportError:
        from system_scanner import SystemScanner
        from cve_fetcher import CVEFetcher
        from package_mapper import PackageMapper
    
    scanner = SystemScanner()
    installed = scanner.get_installed_packages()
    
    fetcher = CVEFetcher()
    data = fetcher.fetch_usn_data(limit=50)
    
    mapper = PackageMapper(data)
    mapped_vulns = mapper.map_cves_to_packages()
    
    checker = PatchChecker()
    findings = checker.check_system(installed, mapped_vulns)
    
    print(f"[*] Total vulnerabilities found: {len(findings)}")
    # Safely iterate up to 3 elements to satisfy strict type checkers about slices
    for idx, f in enumerate(findings):
         if idx >= 3:
             break
         print(f)
