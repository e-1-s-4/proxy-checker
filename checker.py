import requests
import concurrent.futures

INPUT_FILE = "unchecked.txt"
OUTPUT_FILE = "checked.txt"

TEST_URLS = [
    "http://httpbin.org/ip",
    "http://www.google.com",
    "http://www.bing.com",
    "http://example.com"
]

TIMEOUT = 10  # seconds

def check_proxy(proxy):
    proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
    headers = {"User-Agent": "Mozilla/5.0"}  # disguise as browser

    for url in TEST_URLS:
        try:
            response = requests.get(url, proxies=proxies, headers=headers, timeout=TIMEOUT)
            if response.status_code == 200:
                print(f"[+] WORKING: {proxy} ({url})")
                return proxy  # ✅ stop after first success
        except:
            continue

    print(f"[-] DEAD: {proxy}")
    return None

def main():
    with open(INPUT_FILE, "r") as f:
        proxy_list = f.read().splitlines()

    working_proxies = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(check_proxy, proxy_list)
        for result in results:
            if result:
                working_proxies.append(result)

    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(working_proxies))

    print(f"\n✅ Done! {len(working_proxies)} working proxies saved in {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
