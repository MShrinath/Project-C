import requests
import re
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin


def scan_website(url):
    try:
        results = []

        # Step 1: Discover URLs
        discovered_urls = discover_urls(url)
        print(f"Discovered {len(discovered_urls)} URLs on {url}:\n")
        for i, discovered_url in enumerate(discovered_urls, start=1):
            print(f"{i}. {discovered_url}")

        # Step 2: Scan for vulnerabilities
        for page_url in discovered_urls:
            vulnerabilities = scan_url(page_url)
            results.append({
                "url": page_url,
                "vulnerabilities": vulnerabilities if vulnerabilities else "No vulnerabilities found"
            })
            if vulnerabilities:
                print(f"\nVulnerabilities found on {page_url}:")
                for vulnerability, attack_method in vulnerabilities.items():
                    print(f"  - {vulnerability}: {attack_method}")

        # Step 3: Save results to JSON
        save_results_to_json(results, "vulnerability_scan_results.json")
        print("\nScan results saved to 'vulnerability_scan_results.json'.")
    except Exception as e:
        print(f"An error occurred: {e}")


def discover_urls(url):
    discovered_urls = []
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        for anchor_tag in soup.find_all("a"):
            href = anchor_tag.get("href")
            if href:
                absolute_url = urljoin(url, href)
                discovered_urls.append(absolute_url)
    except requests.exceptions.RequestException as e:
        print(f"Error discovering URLs: {e}")
    return discovered_urls


def scan_url(url):
    vulnerabilities = {}
    try:
        # Check for SQL injection
        if is_sql_injection_vulnerable(url):
            vulnerabilities["SQL Injection"] = "SQL code injection in input fields"

        # Check for XSS
        if is_xss_vulnerable(url):
            vulnerabilities["Cross-Site Scripting (XSS)"] = "Malicious script injection in input fields"

        # Check for insecure server configuration
        if has_insecure_configuration(url):
            vulnerabilities["Insecure Server Configuration"] = "Non-secure HTTP protocol detected"
    except Exception as e:
        print(f"Error scanning URL: {url}. Details: {e}")
    return vulnerabilities


def is_sql_injection_vulnerable(url):
    payload = "' OR '1'='1"
    try:
        response = requests.get(f"{url}?id={payload}", timeout=10)
        if re.search(r"error|warning", response.text, re.IGNORECASE):
            return True
    except requests.exceptions.RequestException:
        pass
    return False


def is_xss_vulnerable(url):
    payload = "<script>alert('XSS')</script>"
    try:
        response = requests.get(f"{url}?input={payload}", timeout=10)
        if payload in response.text:
            return True
    except requests.exceptions.RequestException:
        pass
    return False


def has_insecure_configuration(url):
    return not url.startswith("https")


def save_results_to_json(results, file_name):
    try:
        with open(file_name, "w") as json_file:
            json.dump(results, json_file, indent=4)
    except Exception as e:
        print(f"Error saving results to JSON: {e}")


# Example usage
if __name__ == "__main__":
    scan_website("https://www.example.com")

    # Credits
    print("\n#############################################")
    print("Script by: Mejbaur Bahar Fagun")
    print("#############################################")
