import subprocess
from typing import Dict, List

class SystemScanner:
    def __init__(self):
        # Explicit warning about OS assumption
        pass

    def get_os_release(self) -> str:
        """
        Attempts to detect the Ubuntu codename (e.g., 'jammy', 'focal').
        Defaults to 'jammy' if detection fails or on non-Linux systems.
        """
        import os
        try:
            # Try /etc/os-release first
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release", "r") as f:
                    for line in f:
                        if line.startswith("VERSION_CODENAME="):
                            return line.strip().split("=")[1].strip('"')
            
            # Fallback to lsb_release if available
            result = subprocess.run(["lsb_release", "-cs"], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return "jammy" # Safe default fallback

    def load_from_file(self, filepath: str) -> Dict[str, str]:
        """Loads a package list from a file (format: 'package_name version')."""
        import os
        packages = {}
        if not os.path.exists(filepath):
            return packages
            
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    packages[parts[0]] = parts[1]
        return packages

    def get_installed_packages(self, mock=False):
        """
        Executes read-only dpkg command to list installed packages.
        Returns a dictionary of {package_name: version}
        """
        if mock:
            return self.get_mock_packages()
            
        packages = {}
        try:
            # dpkg-query -W -f='${Package} ${Version}\n'
            result = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package} ${Version}\\n"],
                capture_output=True, text=True, check=True, timeout=10
            )
            for line in result.stdout.splitlines():
                if line.strip():
                    parts = line.split(maxsplit=1)
                    if len(parts) == 2:
                        packages[parts[0]] = parts[1]
            return packages
        except (FileNotFoundError, subprocess.SubprocessError):
            return {}
        except Exception as e:
            print(f"[!] Error executing system scan: {e}")
            return {}

    def get_mock_packages(self):
        """Returns a set of common packages with older versions for demonstration."""
        return {
            "linux-image-generic": "5.15.0.22.25",
            "openssl": "1.1.1f-1ubuntu2",
            "python3-minimal": "3.10.4-0ubuntu2",
            "bash": "5.1-6ubuntu1",
            "git": "2.34.1-1ubuntu1",
            "curl": "7.81.0-1ubuntu1",
            "libexiv2-27": "0.27.2-8ubuntu2.7",
            "freerdp2-x11": "2.6.1+dfsg1-3ubuntu2",
            "glance": "2:24.0.0-0ubuntu1"
        }

if __name__ == "__main__":
    scanner = SystemScanner()
    pkgs = scanner.get_installed_packages()
    print(f"[*] Detected {len(pkgs)} installed packages.")
    items = list(pkgs.items())
    if len(items) > 0:
        print("Sample packages:")
        for pkg, ver in items[:5]:
            print(f"  {pkg}: {ver}")
