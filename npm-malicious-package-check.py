#!/usr/bin/env python3
"""
USAGE
    python3 npm-malicious-package-check.py

DESCRIPTION
    Walk the filesystem starting at / and look for malicious NPM packages.
"""

import csv
import io
import json
import os
import socket
import sys
import time

from urllib import request

OSSF_MAL_PACKAGE_DB_URL = (
    "https://raw.githubusercontent.com/Red-Hat-Information-Security/Incident-Response/"
    "refs/heads/main/data/ossf-malicious-npm-packages.txt"
)

RHIS_MAL_PACKAGE_DB_URL = (
    "https://raw.githubusercontent.com/Red-Hat-Information-Security/Incident-Response/"
    "refs/heads/main/data/rhis-malicious-npm-packages.csv"
)

DISCLAIMER = """
===============================================================================
DISCLAIMER
-------------------------------------------------------------------------------
This script can miss things. It's meant to be a basic check against packages
in the following sources with specific versions listed:

- https://github.com/ossf/malicious-packages
- https://github.com/red-hat-information-security/incident-response
===============================================================================
"""


def _load_json_file_path(json_file_path):
    try:
        with open(json_file_path, encoding="UTF-8") as json_file:
            return json.load(json_file)
    except Exception:
        return {}


def _load_package_version(package_json_path):
    try:
        package_json_data = _load_json_file_path(package_json_path)
        name = package_json_data["name"].lower()
        version = package_json_data["version"].lower()

        if name and version:
            return f"{name}@{version}"
    except Exception:
        pass

    return None


def _load_malicious_npm_packages():
    malicious_packages = {}  # format malicious_packages["name@version] = "comment"
    print("Fetching OSSF malicious package db...")
    with request.urlopen(OSSF_MAL_PACKAGE_DB_URL) as response:
        if response.status == 200:
            print("Loading OSSF malicious package db...")
            package_comment = "Marked Malicious by the OSSF"
            for package in response:
                package_id = package.decode().strip()
                malicious_packages[package_id] = package_comment
        else:
            print("Unable to fetch OSSF's malicious package db")

    print("Fetching RHIS malicious package db...")
    with request.urlopen(RHIS_MAL_PACKAGE_DB_URL) as response:
        if response.status == 200:
            print("Loading RHIS malicious package db...")
            response_text = io.TextIOWrapper(response, encoding="UTF-8")
            for row in csv.DictReader(response_text):
                package_id = f"{row['package_name']}@{row['package_version']}"
                package_comment = "Campaign: " + row["campaign_name"]
                malicious_packages[package_id] = package_comment
        else:
            print("Unable to fetch RHIS's malicious package db")

    if len(malicious_packages) == 0:
        print("ERROR: Unable to fetch package DBs")
        sys.exit(1)

    return malicious_packages


def main():
    """main entrypoint to the script"""
    scan_root = "/"
    if len(sys.argv) == 2:
        scan_root = os.path.abspath(sys.argv[1])

    malicious_packages = _load_malicious_npm_packages()
    package_json_paths = (
        os.path.join(dirpath, filename)
        for dirpath, dirnames, filenames in os.walk(scan_root)
        for filename in filenames
        if filename == "package.json"
    )

    print("Scanning installed npm packages...\n")
    found = False
    for package_json_path in package_json_paths:
        package_version = _load_package_version(package_json_path)
        if not package_version:
            continue

        if package_version in malicious_packages:
            package_comment = malicious_packages[package_version]
            if not found:
                print(
                    "\033[1m[\033[91mWARNING\033[0m\033[1m] Malicious Package(s) Found:\033[0m\n"
                )

            print("- Package:", package_version)
            print("  Details:", package_comment)
            print("  Location:", package_json_path)
            print()
            found = True

    if not found:
        print("\033[1m[\033[92mPHEW\033[0m\033[1m] No malicious packages found")
    else:
        print(
            "\033[1m[\033[93mIMPORTANT\033[0m\033[1m] "
            "Please include the following in your ticket to InfoSec:\033[0m\n"
        )
        print("- \033[1mALL OF THE SCRIPT OUTPUT ABOVE\033[0m")
        print("- Username:", os.getlogin())
        print("- Hostname:", socket.gethostname())
        print("- Timestamp:", int(time.time()))


if __name__ == "__main__":
    print(DISCLAIMER)
    main()
