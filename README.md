# Clickjacking Detector

## Overview

The Clickjacking Detector is a Python utility that checks websites for clickjacking vulnerabilities by analyzing HTTP headers and checking for iframes in the HTML. It utilizes the `requests` and `BeautifulSoup` libraries to perform its checks and provides a user-friendly interface with color-coded output.

## Features

- Checks for the presence of `X-Frame-Options` and `Content-Security-Policy` headers.
- Analyzes the HTML for any `iframe` elements.
- Provides clear and color-coded output for easy understanding of vulnerability status.
- Allows users to scan multiple websites in a single session.

## Requirements

- Python 3.x
- `requests` library
- `beautifulsoup4` library
- `colorama` library

You can install the required libraries using pip:

```bash
pip3 install requests beautifulsoup4 colorama
```

## Usage

Clone the repository:
```bash
git clone https://github.com/MrMihasha/clickjacking-detector
cd clickjacking-detector
```
Run the script:
```bash
python3 cjdetector.py
```
Enter the URL of the site you want to check when prompted.
