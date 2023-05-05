import requests

# List of common vulnerabilities to check for
vulnerabilities = [
    "SQL Injection",
    "Cross-site Scripting (XSS)",
    "Remote Code Execution (RCE)",
    "File Inclusion",
    "Server-Side Request Forgery (SSRF)"
]

# Define a function to check for SQL Injection vulnerability
def check_sql_injection(url):
    # Add a single quote (') to the end of the URL to see if it's vulnerable
    sql_injection_payload = url + "'"
    response = requests.get(sql_injection_payload)
    if "syntax error" in response.text:
        print("[!] SQL Injection vulnerability found:", url)

# Define a function to check for Cross-site Scripting (XSS) vulnerability
def check_xss(url):
    # Inject a script tag into a query string parameter to see if it's vulnerable
    xss_payload = url + "?q=<script>alert('XSS')</script>"
    response = requests.get(xss_payload)
    if "<script>alert('XSS')</script>" in response.text:
        print("[!] Cross-site Scripting (XSS) vulnerability found:", url)

# Define a function to check for Remote Code Execution (RCE) vulnerability
def check_rce(url):
    # Inject a command to the system shell to see if it's vulnerable
    rce_payload = url + "?q=$(id)"
    response = requests.get(rce_payload)
    if "uid=" in response.text:
        print("[!] Remote Code Execution (RCE) vulnerability found:", url)

# Define a function to check for File Inclusion vulnerability
def check_file_inclusion(url):
    # Include a file using a relative path to see if it's vulnerable
    file_inclusion_payload = url + "?file=../../../../etc/passwd"
    response = requests.get(file_inclusion_payload)
    if "root:x:" in response.text:
        print("[!] File Inclusion vulnerability found:", url)

# Define a function to check for Server-Side Request Forgery (SSRF) vulnerability
def check_ssrf(url):
    # Request an internal IP address to see if it's vulnerable
    ssrf_payload = url + "?url=http://127.0.0.1"
    response = requests.get(ssrf_payload)
    if "127.0.0.1" in response.text:
        print("[!] Server-Side Request Forgery (SSRF) vulnerability found:", url)

# Define a function to run all vulnerability checks for a given URL
def scan_url(url):
    print("[*] Scanning:", url)
    check_sql_injection(url)
    check_xss(url)
    check_rce(url)
    check_file_inclusion(url)
    check_ssrf(url)
    print("[*] Scan complete.")

# Example usage: scan the target website
scan_url("http://example.com")