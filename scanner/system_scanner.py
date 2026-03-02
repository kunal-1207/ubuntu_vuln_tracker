import subprocess

class SystemScanner:
    def __init__(self):
        # Explicit warning about OS assumption
        pass

    def get_installed_packages(self):
        """
        Executes read-only dpkg command to list installed packages.
        Returns a dictionary of {package_name: version}
        """
        packages = {}
        try:
            # dpkg-query -W -f='${Package} ${Version}\n'
            result = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package} ${Version}\\n"],
                capture_output=True, text=True, check=True
            )
            for line in result.stdout.splitlines():
                if line.strip():
                    parts = line.split(maxsplit=1)
                    if len(parts) == 2:
                        packages[parts[0]] = parts[1]
            return packages
        except FileNotFoundError:
            print("[!] dpkg-query not found. Are you running this on Debian/Ubuntu or WSL?")
            return {}
        except Exception as e:
            print(f"[!] Error executing system scan: {e}")
            return {}

if __name__ == "__main__":
    scanner = SystemScanner()
    pkgs = scanner.get_installed_packages()
    print(f"[*] Detected {len(pkgs)} installed packages.")
    items = list(pkgs.items())
    if len(items) > 0:
        print("Sample packages:")
        for pkg, ver in items[:5]:
            print(f"  {pkg}: {ver}")
