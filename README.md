# YES
ONLY HTTP(S)
Sure! Here's a professional and clear **README.md** you can use for your proxy checker script:

````markdown
# Proxy Checker

A simple Python script to check the availability of proxies by testing them against multiple websites concurrently. The script reads proxies from a file, tests them, and saves the working ones to another file.

---

## Features

- Tests proxies against multiple URLs (`http://httpbin.org/ip`, `http://www.google.com`, `http://www.bing.com`, `http://example.com`).
- Uses concurrent threads for faster checking.
- Saves only working proxies to a separate output file.
- Automatically stops testing a proxy after the first successful connection.

---

## Requirements

- Python 3.7 or higher
- `requests` library

Install dependencies with:

```bash
pip install requests
````

---
After runing example
<img width="580" height="190" alt="image" src="https://github.com/user-attachments/assets/c4f0011a-86a3-4548-ac5c-637d6a4cb73b" />

## Usage

1. Create a file named `unchecked.txt` in the same directory and add one proxy per line. Example format:

```
127.0.0.1:8080
192.168.1.1:3128
```

2. Run the script:

```bash
python proxy_checker.py
```

3. After execution, working proxies will be saved in `checked.txt`.

---

## Configuration

* `INPUT_FILE`: Name of the file containing proxies to check (default: `unchecked.txt`)
* `OUTPUT_FILE`: Name of the file to save working proxies (default: `checked.txt`)
* `TEST_URLS`: List of URLs to test proxies against
* `TIMEOUT`: Timeout for each request in seconds (default: 10)
* `max_workers`: Number of concurrent threads (default: 100)

You can edit these values directly in the script to suit your needs.

---

## Notes

* Only HTTP and HTTPS proxies are supported.
* The script prints a log of working (`[+] WORKING`) and dead (`[-] DEAD`) proxies.
* Be respectful when testing proxies and avoid overloading servers with too many requests.

---

## License

This project is released under the MIT License.

```

---



