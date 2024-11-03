#!/usr/bin/env python3

import re
import os
import argparse
import requests

# ANSI escape codes for coloring
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"
YELLOW = "\033[93m"

# Define patterns for potential XSS vulnerabilities
patterns = {
    # General JavaScript vulnerabilities
    "document_write": {
        "pattern": r"\bdocument\.write\b",
        "explanation": "Using 'document.write' can overwrite the entire document if executed after the page has loaded."
    },
    "innerHTML": {
        "pattern": r"\binnerHTML\b",
        "explanation": "Using 'innerHTML' can allow for injection of HTML content, making it possible to execute malicious scripts."
    },
    "eval": {
        "pattern": r"\beval\b",
        "explanation": "'eval' executes a string as code, which can be exploited if the string contains user-controlled input."
    },
    "setTimeout": {
        "pattern": r"\bsetTimeout\b",
        "explanation": "'setTimeout' can execute code after a delay, which may lead to unexpected behavior if used with user input."
    },
    "setInterval": {
        "pattern": r"\bsetInterval\b",
        "explanation": "'setInterval' repeatedly executes code at specified intervals, which can lead to security risks if input is not controlled."
    },
    "location_href": {
        "pattern": r"\blocation\.href\b",
        "explanation": "Modifying 'location.href' can redirect users to malicious sites if user input is not sanitized."
    },
    "innerHTML_assignment": {
        "pattern": r"\binnerHTML\s*=\s*['\"]",
        "explanation": "Directly assigning to 'innerHTML' allows for potential script injection if the value is not properly validated."
    },
    "element_property_assignment": {
        "pattern": r"\.(src|href|action)\s*=\s*['\"]",
        "explanation": "Assigning untrusted data to element properties like 'src' or 'href' can lead to redirection or content injection."
    },
    
    # DOM-based XSS patterns
    "document_getElementById": {
        "pattern": r"\bdocument\.getElementById\b",
        "explanation": "Using this method can allow access to elements and manipulation of their properties, which may include untrusted data."
    },
    "document_getElementsByClassName": {
        "pattern": r"\bdocument\.getElementsByClassName\b",
        "explanation": "Similar to getElementById, this can manipulate elements based on classes, potentially leading to XSS if not handled properly."
    },
    "document_getElementsByTagName": {
        "pattern": r"\bdocument\.getElementsByTagName\b",
        "explanation": "Accessing elements by tag can expose them to injection if not filtered."
    },
    "query_selector": {
        "pattern": r"\bdocument\.querySelector\b",
        "explanation": "Using querySelector can allow for dynamic selection of elements and manipulation, leading to potential vulnerabilities."
    },
    "query_selector_all": {
        "pattern": r"\bdocument\.querySelectorAll\b",
        "explanation": "Similar to querySelector, but returns all matches, increasing the risk of manipulation."
    },
    "window_location": {
        "pattern": r"\bwindow\.location\b",
        "explanation": "Manipulating 'window.location' can lead to redirects and exposure to XSS if values are not controlled."
    },
    "document_location": {
        "pattern": r"\bdocument\.location\b",
        "explanation": "Similar to window.location, altering document location can be risky with unvalidated inputs."
    },
    
    # Tag injection patterns
    "script_tag_injection": {
        "pattern": r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>",
        "explanation": "Direct script injection is a clear XSS risk, allowing for execution of arbitrary JavaScript."
    },
    "iframe_injection": {
        "pattern": r"<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>",
        "explanation": "Inserting iframes can lead to clickjacking or loading malicious content."
    },
    "img_tag_injection": {
        "pattern": r"<img\b[^<]*(?:(?!\/?>)<[^<]*)*\/?>",
        "explanation": "Improperly validated image sources can lead to XSS through image loading and event handling."
    },
    "h1_tag_injection": {
        "pattern": r"<h1\b[^<]*(?:(?!<\/h1>)<[^<]*)*<\/h1>",
        "explanation": "Headers can be manipulated to include scripts, leading to XSS."
    },
    "h2_tag_injection": {
        "pattern": r"<h2\b[^<]*(?:(?!<\/h2>)<[^<]*)*<\/h2>",
        "explanation": "Similar to h1, these can contain injected scripts."
    },
    "h3_tag_injection": {
        "pattern": r"<h3\b[^<]*(?:(?!<\/h3>)<[^<]*)*<\/h3>",
        "explanation": "Headings can also be vectors for XSS through script injection."
    },
    "h4_tag_injection": {
        "pattern": r"<h4\b[^<]*(?:(?!<\/h4>)<[^<]*)*<\/h4>",
        "explanation": "Script injection in headings can execute malicious scripts."
    },
    "h5_tag_injection": {
        "pattern": r"<h5\b[^<]*(?:(?!<\/h5>)<[^<]*)*<\/h5>",
        "explanation": "Allows for potential XSS if scripts are injected."
    },
    "h6_tag_injection": {
        "pattern": r"<h6\b[^<]*(?:(?!<\/h6>)<[^<]*)*<\/h6>",
        "explanation": "Similar risks as other heading tags regarding script injection."
    },
    
    # Event handler vulnerabilities
    "onerror": {
        "pattern": r"\bonerror\s*=\s*['\"]",
        "explanation": "Event handlers like 'onerror' can execute malicious code if user input is included."
    },
    "onclick": {
        "pattern": r"\bonclick\s*=\s*['\"]",
        "explanation": "Click event handlers can be exploited for XSS if untrusted input is processed."
    },
    "onload": {
        "pattern": r"\bonload\s*=\s*['\"]",
        "explanation": "Loading events can execute scripts, leading to XSS if the source is untrusted."
    },
    "onmouseover": {
        "pattern": r"\bonmouseover\s*=\s*['\"]",
        "explanation": "Mouse events can trigger scripts that may contain user-controlled input."
    },
    "onfocus": {
        "pattern": r"\bonfocus\s*=\s*['\"]",
        "explanation": "Focus events can lead to unintended script execution with unvalidated input."
    },
    
    # Other potential vulnerabilities
    "style_attribute": {
        "pattern": r"\bstyle\s*=\s*['\"]",
        "explanation": "Inline styles can include scripts if not properly sanitized."
    },
    "data_attribute": {
        "pattern": r"\bdata-.*?=\s*['\"]",
        "explanation": "Data attributes can hold unvalidated data, potentially leading to XSS."
    },
    "location_replace": {
        "pattern": r"\blocation\.replace\b",
        "explanation": "Using 'location.replace' with untrusted data can redirect users maliciously."
    },
    "document_cookie": {
        "pattern": r"\bdocument\.cookie\b",
        "explanation": "Manipulating cookies can lead to XSS if not handled correctly."
    },
    "innerHTML_function": {
        "pattern": r"\binnerHTML\s*\(\s*['\"]",
        "explanation": "Function calls using 'innerHTML' can inject scripts through user-controlled strings."
    },
    "json_parse": {
        "pattern": r"\bJSON\.parse\b",
        "explanation": "Parsing JSON from untrusted sources can lead to execution of arbitrary code."
    },
    "function_constructor": {
        "pattern": r"\bFunction\s*\(",
        "explanation": "Using the Function constructor with user input can execute arbitrary code."
    },
    "response_text": {
        "pattern": r"\bresponseText\b",
        "explanation": "'responseText' can contain untrusted data, leading to potential script execution."
    },
    "fetch_api": {
        "pattern": r"\bfetch\b",
        "explanation": "'fetch' requests can return user-controlled data that may be misused."
    },
    "response_json": {
        "pattern": r"\bresponse\.json\b",
        "explanation": "Parsing JSON responses can lead to vulnerabilities if the data includes scripts."
    },
}

def scan_for_xss(js_code, file_name):
    # Dictionary to store findings
    findings = {}
    for name, details in patterns.items():
        matches = re.findall(details['pattern'], js_code)
        if matches:
            findings[name] = {
                "matches": matches,
                "explanation": details["explanation"]
            }

    if findings:
        print(f"\n{RED}[ Potential XSS vulnerabilities found in ] :{RESET} {BLUE}{file_name}:{RESET}\n")
        for name, details in findings.items():
            print(f"  - {name}: {len(details['matches'])} occurrence(s)")
            print(f"    Explanation: {details['explanation']}")
    else:
        print(f"\n{YELLOW}[ No potential XSS vulnerabilities found in ] :{RESET} {BLUE}{file_name}:{RESET}\n")

def scan_file_from_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for bad responses
        js_code = response.text
        file_name = url.split("/")[-1]  # Get the file name from URL
        scan_for_xss(js_code, file_name)
    except requests.RequestException as e:
        print(f"Failed to fetch {url}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Scan JavaScript files for potential XSS vulnerabilities.")
    parser.add_argument("--file_path", required=True, help="Path to the text file containing URLs of JavaScript files.")
    args = parser.parse_args()

    # Check if the file exists
    if not os.path.isfile(args.file_path):
        print(f"Error: The file '{args.file_path}' does not exist.")
        return

    try:
        # Read URLs from the provided file path
        with open(args.file_path, 'r') as file:
            urls = file.readlines()

        for url in urls:
            url = url.strip()  # Remove any leading/trailing whitespace
            if url:  # Skip empty lines
                scan_file_from_url(url)

    except KeyboardInterrupt:
        print("\nProcess interrupted by user. Exiting gracefully.")

if __name__ == "__main__":
    main()
