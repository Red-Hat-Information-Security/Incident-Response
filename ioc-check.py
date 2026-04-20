#!/usr/bin/env python3
"""
USAGE
    python3 ioc-check.py

DESCRIPTION
    Walk the filesystem starting at / and look for known indicators of compromise (IoCs).

NOTES
    Package findings are displayed using the PURL[1] syntax.

    [1]: https://github.com/package-url/purl-spec
"""

import csv
import fnmatch
import io
import json
import os
import re
import socket
import sys
import time

from urllib import request
from urllib.parse import quote

DB_REF = os.environ.get("RHIS_IOC_CHECK_DB_REF", "refs/heads/main")

RHIS_MAL_PACKAGE_DB_URL = (
    "https://raw.githubusercontent.com/Red-Hat-Information-Security/Incident-Response/"
    f"{DB_REF}/data/rhis-malicious-packages.csv"
)
RHIS_HOST_IOC_DB_URL = (
    "https://raw.githubusercontent.com/Red-Hat-Information-Security/Incident-Response/"
    f"{DB_REF}/data/rhis-host-iocs.csv"
)

DISCLAIMER = """
===============================================================================
DISCLAIMER
-------------------------------------------------------------------------------
This script can miss things. This script looks indicators of compromise listed
in: 

https://github.com/Red-Hat-Information-Security/Incident-Response/tree/main/data
===============================================================================

WARNING: On Mac you may be asked to provide your terminal program access to
other parts of the system. This script attempts to scan the whole system, this
is why you are seeing these requests. The scan will be more effective with
access to the whole system.
"""


def _new_purl(pkg_type, pkg_name, pkg_version):
    """
    Basic helper function for creating PURLs (https://github.com/package-url/purl-spec)
    """
    pkg_type = pkg_type.lower()
    pkg_name = quote(pkg_name)
    return f"pkg:{pkg_type}/{pkg_name}@{pkg_version}"


def _load_npm_pkg_info(pkg_info_path):
    """
    Load package.json files
    """
    try:
        with open(pkg_info_path, encoding="UTF-8") as pkg_info_file:
            return json.load(pkg_info_file)
    except Exception:
        return {}


def _load_pypi_pkg_info(pkg_info_path):
    """
    Load *dist-info/METADATA and *egg-info/PKG-INFO files
    """
    pkg_info = {}

    try:
        with open(pkg_info_path, encoding="UTF-8") as pkg_info_file:
            for line in map(str.strip, pkg_info_file):
                if not line:
                    break

                key, value = line.split(":", 1)
                pkg_info[key.strip().lower()] = value.strip()
    except Exception:
        pass

    return pkg_info


def _load_pkg_purl(pkg_type, pkg_info_path):
    """
    Look up a package info load function, load the information and get a PURL for the package

    Returns PURL string on success and None on error
    """
    try:
        load_pkg_info = globals()[f"_load_{pkg_type}_pkg_info"]
    except Exception:
        print(f'ERROR: could not find loader: pkg_type="{pkg_type}"')
        return None

    try:
        pkg_info = load_pkg_info(pkg_info_path)
        name = pkg_info["name"].lower()
        version = pkg_info["version"].lower()
        if name and version:
            return _new_purl(pkg_type, name, version)
    except Exception:
        pass

    return None


def _check_pkg(malicious_packages, pkg_type, filepath):
    purl = _load_pkg_purl(pkg_type, filepath)

    if not purl or purl not in malicious_packages:
        return None

    return {
        "path": filepath,
        "finding": "Malicious Package: " + purl,
        "notes": malicious_packages[purl],
    }


def _load_malicious_packages():
    malicious_packages = {}  # format malicious_packages[purl] = notes

    print("Fetching RHIS malicious package db...")
    with request.urlopen(RHIS_MAL_PACKAGE_DB_URL) as response:
        if response.status == 200:
            print("Loading RHIS malicious package db...")
            response_text = io.TextIOWrapper(response, encoding="UTF-8")

            for row in csv.DictReader(response_text):
                purl = _new_purl(
                    row["package_type"], row["package_name"], row["package_version"]
                )

                if purl in malicious_packages:
                    malicious_packages[purl] += f", {row['campaign_name']}"
                else:
                    malicious_packages[purl] = "Campaign(s): " + row["campaign_name"]
        else:
            print("Unable to fetch RHIS's malicious package db")

    if len(malicious_packages) == 0:
        print("ERROR: Unable to fetch package DBs")
        sys.exit(1)

    return malicious_packages


def _load_malicious_package_host_iocs():
    print("Fetching RHIS Host IoC db...")
    with request.urlopen(RHIS_HOST_IOC_DB_URL) as response:
        if response.status != 200:
            print("Unable to fetch RHIS's Host IoC db")
            return []

        print("Loading RHIS Host IoC db...")
        response_text = io.TextIOWrapper(response, encoding="UTF-8")
        iocs = list(csv.DictReader(response_text))
        path_types = {"directory", "file"}

        for ioc in iocs:
            if ioc["ioc_type"] in path_types:
                # Expand user and turn globs into regexes
                glob_pattern = os.path.expanduser(os.path.expandvars(ioc["ioc_value"]))
                regex_pattern = fnmatch.translate(glob_pattern)
                if "**" in glob_pattern:
                    regex_pattern = regex_pattern.replace(
                        # Find the pattern for a single '*'
                        fnmatch.translate("*")[: -len("$")],
                        ".*",
                    )
                ioc["ioc_value"] = re.compile(regex_pattern)

        return iocs


def _check_host_iocs(host_path_iocs, path):
    for ioc in host_path_iocs:
        if ioc["ioc_value"].match(path):
            return {
                "path": path,
                "finding": "Host IoC: " + ioc["ioc_description"],
                "notes": "Campaign: " + ioc["campaign_name"],
            }

    return None


def _check_iocs(scan_root):
    malicious_packages = _load_malicious_packages()
    host_iocs = _load_malicious_package_host_iocs()
    host_file_iocs = [ioc for ioc in host_iocs if ioc["ioc_type"] == "file"]
    host_dir_iocs = [ioc for ioc in host_iocs if ioc["ioc_type"] == "directory"]

    print("Scanning for Indicators of Compromise (IoCs)...\n")
    for dirpath, _, filenames in os.walk(scan_root):
        dir_finding = _check_host_iocs(host_dir_iocs, dirpath)
        if dir_finding:
            yield dir_finding

        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            parentname = os.path.basename(dirpath)

            pkg_type = None
            if filename == "package.json":
                pkg_type = "npm"
            elif filename == "METADATA" and parentname.endswith(".dist-info"):
                pkg_type = "pypi"
            elif filename == "PKG-INFO" and parentname.endswith(".egg-info"):
                pkg_type = "pypi"

            if pkg_type:
                pkg_finding = _check_pkg(malicious_packages, pkg_type, filepath)
                if pkg_finding:
                    yield pkg_finding

            file_finding = _check_host_iocs(host_file_iocs, filepath)
            if file_finding:
                yield file_finding


def main():
    scan_root = "/"
    if len(sys.argv) == 2:
        scan_root = os.path.abspath(sys.argv[1])

    found = False
    for finding in _check_iocs(scan_root):
        if not found:
            found = True
            print(
                "\033[1m[\033[91mWARNING\033[0m\033[1m] Malicious Package IoC(s) Found:\033[0m\n"
            )

        print("- Finding:", finding["finding"])
        print("  Notes:", finding["notes"])
        print("  Location:", finding["path"])
        print()

    if not found:
        print("\033[1m[\033[92mPHEW\033[0m\033[1m] No malicious packages found\033[0m")
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
