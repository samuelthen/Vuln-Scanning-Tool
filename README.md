# Vulnerability Scanning Tool

A web vulnerability scanning tool inspired by OWASP ZAP, combining passive and active scanning capabilities to identify security vulnerabilities in web applications.

## Features

- **Passive Scanning**: Analyzes web application responses for potential security issues without sending malicious requests
- **Active Scanning**: Actively probes web applications for vulnerabilities (in development)
- **Web Crawling**: Advanced web spider with configurable depth and thread limits
- **Risk Assessment**: Categorizes vulnerabilities by risk level (High, Medium, Low, Informational)
- **Detailed Reporting**: Generates comprehensive JSON reports with evidence and references

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/vuln-scanning-tool.git
cd vuln-scanning-tool
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run a basic scan:
```bash
python main.py
```

The tool will:
1. Crawl the target website
2. Perform passive vulnerability scanning
3. Generate a detailed report in `scan_results.json`

## Configuration

You can modify the following parameters in `main.py`:
- `start_url`: Target website URL
- `max_pages`: Maximum number of pages to crawl
- `max_depth`: Maximum crawl depth
- `max_threads`: Number of concurrent threads
- `query_param_handling`: Query parameter handling strategy

## Project Structure

```
├── src/
│   ├── passive_scan/     # Passive scanning modules
│   ├── active_scan/      # Active scanning modules
│   └── spider/          # Web crawling functionality
├── tests/               # Test suite
├── main.py             # Main entry point
├── run_scan.py         # Scanning execution script
└── requirements.txt    # Project dependencies
```

## Acknowledgments

This project is inspired by OWASP ZAP (https://www.zaproxy.org/), an open-source web application security scanner.

## Security

Please note that this tool is for authorized security testing only. Always:
- Obtain proper authorization before scanning any website
- Follow responsible disclosure practices
- Respect rate limits and scanning policies
- Do not use for malicious purposes

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this program. 