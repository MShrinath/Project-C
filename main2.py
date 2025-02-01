import requests
import re 
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from jinja2 import Environment, FileSystemLoader 

def scan_website(url):
    try:
        results = []
        discovered_urls = discover_urls(url)
        for page_url in discovered_urls:
            vulnerabilities = scan_url(page_url)
            results.append({
                "url": page_url,
                "vulnerabilities": vulnerabilities if vulnerabilities else "No vulnerabilities found"
            })
        website_name = url.replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]
        generate_html_report(url, results, website_name)
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
        if is_sql_injection_vulnerable(url):
            vulnerabilities["SQL Injection"] = "SQL code injection in input fields"
        if is_xss_vulnerable(url):
            vulnerabilities["Cross-Site Scripting (XSS)"] = "Malicious script injection in input fields"
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

def generate_html_report(website_url, results, website_name):
    env = Environment(loader=FileSystemLoader("."))
    template = env.get_template("report_template.html")
    report_html = template.render(website_url=website_url, results=results)
    report_filename = f"vulnerability_report_{website_name}.html"
    with open(report_filename, "w") as f:
        f.write(report_html)
    print(f"Report saved as '{report_filename}'")

if __name__ == "__main__":
    scan_website("https://example.com/")

