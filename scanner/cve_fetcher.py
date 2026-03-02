import os
import json
import time
import requests

CACHE_FILE = "data/cache.json"
CACHE_EXPIRY = 86400  # 24 hours

class CVEFetcher:
    def __init__(self):
        self.usn_url = "https://ubuntu.com/security/notices.json"
        
    def _is_cache_valid(self):
        if not os.path.exists(CACHE_FILE):
            return False
        return time.time() - os.path.getmtime(CACHE_FILE) < CACHE_EXPIRY

    def _load_cache(self):
        with open(CACHE_FILE, 'r') as f:
            return json.load(f)

    def _save_cache(self, data):
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        with open(CACHE_FILE, 'w') as f:
            json.dump(data, f)
            
    def fetch_usn_data(self, limit=100):
        if self._is_cache_valid():
            return self._load_cache()
            
        print("[*] Fetching latest Ubuntu Security Notices...")
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"}
            response = requests.get(f"{self.usn_url}?limit={limit}", headers=headers)
            response.raise_for_status()
            data = response.json()
            self._save_cache(data)
            return data
        except Exception as e:
            print(f"[!] Error fetching USN data: {e}")
            return None

if __name__ == "__main__":
    fetcher = CVEFetcher()
    data = fetcher.fetch_usn_data()
    if data:
        print(f"[*] Successfully loaded {len(data.get('notices', []))} notices.")
