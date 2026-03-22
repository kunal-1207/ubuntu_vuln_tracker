from typing import Dict, List, Any

class PackageMapper:
    def __init__(self, usn_data: Dict[str, Any]):
        self.usn_data = usn_data
        
    def map_cves_to_packages(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Parses USN data and returns a mapping of:
        {
            package_name: [
                {
                    "cve_id": ["CVE-XXXX-XXXX"],
                    "usn_id": "USN-XXXX-X",
                    "fixed_version": "1.2.3-0ubuntu1",
                    "releases": ["ubuntu-22.04", "ubuntu-24.04"]
                }
            ]
        }
        """
        mapping: Dict[str, List[Dict[str, Any]]] = {}
        if not self.usn_data or not isinstance(self.usn_data.get('notices'), list):
            return mapping
            
        for notice in self.usn_data['notices']:
            usn_id = notice.get('id', 'Unknown USN')
            cve_ids = [cve.get('id') for cve in notice.get('cves', []) if cve.get('id')]
            
            release_packages = notice.get('release_packages', {})
            for release, packages in release_packages.items():
                for pkg_info in packages:
                    pkg_name = pkg_info.get('name')
                    if not pkg_name:
                        continue
                    if pkg_info.get('is_source', False):
                        continue # We only care about binary packages for the system scan ordinarily, but keeping simple
                    
                    fixed_version = pkg_info.get('version', '')
                    
                    if pkg_name not in mapping:
                        mapping[pkg_name] = []
                        
                    mapping[pkg_name].append({
                        "usn_id": usn_id,
                        "cves": cve_ids,
                        "fixed_version": fixed_version,
                        "release": release
                    })
                    
        return mapping

if __name__ == "__main__":
    try:
        from scanner.cve_fetcher import CVEFetcher
    except ImportError:
        from cve_fetcher import CVEFetcher
        
    fetcher = CVEFetcher()
    data = fetcher.fetch_usn_data(limit=10)
    mapper = PackageMapper(data)
    mapping = mapper.map_cves_to_packages()
    print(f"[*] Mapped {len(mapping)} packages to CVEs.")
