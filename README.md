# XSS Vulnerability Scanner

This Python script scans JavaScript files hosted on URLs for potential Cross-Site Scripting (XSS) vulnerabilities. It identifies common patterns in JavaScript code that could be exploited for XSS attacks, providing a quick and automated way to evaluate JavaScript files for potential security issues.

## Features

-   **Pattern-based Scanning**: Detects various JavaScript patterns that are often associated with XSS vulnerabilities, such as `innerHTML`, `eval`, `document.write`, and inline event handlers.
-   **Color-coded Output**: Uses ANSI escape codes to highlight findings, with different colors for identified vulnerabilities, warnings, and other messages.
-   **Command-line Interface**: Allows for easy execution and customization through command-line arguments.
-   **Fetch JavaScript from URLs**: Reads URLs from a file and scans each JavaScript file at the given URL.

## Installation

### Prerequisites

-   Python 3.x
-   `requests` library

Install the `requests` library if it's not already installed:
```
pip install requests
```
## Usage

1.  Create a text file containing URLs of the JavaScript files you want to scan, with each URL on a new line.
2.  Run the script with the file path as an argument.

### Example
```
`python3 xss_scanner.py --file_path /path/to/url_list.txt`
```

### Arguments

-   `--file_path`: Required. Path to the text file containing URLs of JavaScript files to be scanned.

## Output

-   For each URL, the script will display any identified vulnerabilities, with an explanation for each.
-   The output is color-coded:
    -   **Red**: Indicates potential XSS vulnerabilities found.
    -   **Yellow**: Indicates that no vulnerabilities were found in a file.

## Detected Patterns

The script identifies various potential XSS patterns, including but not limited to:
attacks, providing a quick and automated way to evaluate JavaScript files for potential security issues.


-   JavaScript functions and properties (`eval`, `innerHTML`, `setTimeout`, `location.href`)
-   HTML tag injections (`<script>`, `<iframe>`, `<img>`)
-   Event handlers (`onclick`, `onload`, `onerror`)
-   Inline styles and data attributes

Each pattern includes a brief explanation of the associated security risk.

## Limitations

-   **False Positives**: The script is pattern-based and may flag harmless code as potentially vulnerable.
-   **No Remediation**: This script only detects potential vulnerabilities; it does not fix them.

## License

This project is licensed under the MIT License.

## Disclaimer

This script is a tool for preliminary vulnerability scanning and is not a substitute for comprehensive security testing.