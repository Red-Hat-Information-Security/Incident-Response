#!/usr/bin/env python3
"""
USAGE
    python3 shai-hulud-package-check.py [--include-remote] [scan_path]

DESCRIPTION
    Walk the filesystem starting at / and look for Shai-Hulud affected NPM packages.
    By default, skips network and virtual filesystems.

OPTIONS
    --include-remote    Include network and virtual filesystems in scan
    scan_path          Directory to scan (default: /)
"""

import argparse
import csv
import fnmatch
import re
import io
import json
import os
import socket
import sys
import time

from urllib import request

RHIS_MAL_PACKAGE_DB_URL = (
    "https://raw.githubusercontent.com/Red-Hat-Information-Security/Incident-Response/"
    "refs/heads/main/data/rhis-malicious-npm-packages.csv"
)
RHIS_MAL_PACKAGE_IOC_DB_URL = (
    "https://raw.githubusercontent.com/Red-Hat-Information-Security/Incident-Response/"
    "refs/heads/main/data/rhis-malicious-npm-package-host-iocs.csv"
)
DISCLAIMER = """
===============================================================================
DISCLAIMER
-------------------------------------------------------------------------------
This script can miss things. This script specifically looks for packages
affected by the Shai-Hulud campaign and other indicators of compromise. It
checks packages with specific versions listed at the following source:

- https://github.com/red-hat-information-security/incident-response
===============================================================================

WARNING: On Mac you may be asked to provide your terminal program access to
other parts of the system. This script attempts to scan the whole system, this
is why you are seeing these requests. The scan will be more effective with
access to the whole system.
"""

# Filesystem types to skip by default (network and virtual filesystems)
SKIP_FS_TYPES = {
    'nfs', 'nfs4', 'cifs', 'smbfs', 'afs', 'ncpfs',  # Network filesystems
    'proc', 'sysfs', 'devfs', 'devpts', 'tmpfs', 'ramfs',  # Virtual/pseudo filesystems
    'debugfs', 'tracefs', 'securityfs', 'cgroup', 'cgroup2',
    'pstore', 'mqueue', 'hugetlbfs', 'configfs', 'autofs', 'fusectl',
    'binfmt_misc', 'rpc_pipefs', 'fuse.gvfsd-fuse', 'fuse.portal'
}


def _get_mount_points():
    """Get a dictionary of mount points and their filesystem types."""
    mount_points = {}

    # Try to read /proc/mounts on Linux
    try:
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    mount_point = parts[1]
                    fs_type = parts[2]
                    mount_points[mount_point] = fs_type
    except (FileNotFoundError, PermissionError):
        # Fallback: try using mount command or other methods
        pass

    return mount_points


def _should_skip_path(path, mount_points, skip_remote):
    """Check if a path should be skipped based on filesystem type."""
    if not skip_remote:
        return False

    # Find the mount point for this path
    path = os.path.abspath(path)

    # Find the longest matching mount point
    best_match = '/'
    for mount_point in mount_points:
        if path.startswith(mount_point) and len(mount_point) > len(best_match):
            best_match = mount_point

    # Check if the filesystem type should be skipped
    fs_type = mount_points.get(best_match, '')

    # Handle FUSE filesystems (they may have prefixes)
    if fs_type.startswith('fuse.'):
        # Skip most FUSE filesystems except local ones
        if not any(fs_type.startswith(f'fuse.{local}') for local in ['ext', 'btrfs', 'xfs']):
            return fs_type in SKIP_FS_TYPES or any(skip in fs_type for skip in ['gvfs', 'portal', 'remote'])

    return fs_type in SKIP_FS_TYPES


def _load_json_file_path(json_file_path):
    try:
        with open(json_file_path, encoding="UTF-8") as json_file:
            return json.load(json_file)
    except Exception:
        return {}


def _load_package_id(package_json_path):
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
    malicious_packages = {}  # format malicious_packages["name@version] = "context"

    print("Fetching RHIS malicious package db...")
    with request.urlopen(RHIS_MAL_PACKAGE_DB_URL) as response:
        if response.status == 200:
            print("Loading RHIS malicious package db...")
            response_text = io.TextIOWrapper(response, encoding="UTF-8")
            for row in csv.DictReader(response_text):
                package_id = f"{row['package_name']}@{row['package_version']}"
                context = "Campaign: " + row["campaign_name"]
                malicious_packages[package_id] = context
        else:
            print("Unable to fetch RHIS's malicious package db")

    if len(malicious_packages) == 0:
        print("ERROR: Unable to fetch package DBs")
        sys.exit(1)

    return malicious_packages


def _load_malicious_package_host_iocs():
    print("Fetching RHIS malicious package IOC db...")
    with request.urlopen(RHIS_MAL_PACKAGE_IOC_DB_URL) as response:
        if response.status != 200:
            print("Unable to fetch RHIS's malicious package db")
            return []

        print("Loading RHIS malicious package IOC db...")
        response_text = io.TextIOWrapper(response, encoding="UTF-8")
        iocs = list(csv.DictReader(response_text))
        path_types = {"directory", "file"}
        for ioc in iocs:
            if ioc["ioc_type"] in path_types:
                # Expand user and turn globs into regexes
                glob_pattern = os.path.expanduser(ioc["ioc_value"])
                regex_pattern = fnmatch.translate(glob_pattern)
                if '**' in glob_pattern:
                    regex_pattern = regex_pattern.replace(
                        fnmatch.translate('*')[:-len('$')], # Find the pattern for a single '*'
                        '.*'
                    )
                ioc["ioc_value"] = re.compile(regex_pattern)

        return iocs


def _scan_package_json(malicious_packages, filepath):
    if os.path.basename(filepath) != "package.json":
        return None

    package_id = _load_package_id(filepath)
    if not package_id or package_id not in malicious_packages:
        return None

    return {
        "path": filepath,
        "finding": "Malicious Package: " + package_id,
        "context": malicious_packages[package_id],
    }


def _scan_host_path_iocs(host_path_iocs, path):
    for ioc in host_path_iocs:
        if ioc["ioc_value"].match(path):
            return {
                "path": path,
                "finding": "IoC: " + ioc["ioc_description"],
                "context": "Campaign: " + ioc["campaign_name"],
            }

    return None


def _scan_for_iocs(scan_root, skip_remote=True):
    malicious_packages = _load_malicious_npm_packages()
    host_iocs = _load_malicious_package_host_iocs()
    host_file_iocs = [ioc for ioc in host_iocs if ioc["ioc_type"] == "file"]
    host_dir_iocs = [ioc for ioc in host_iocs if ioc["ioc_type"] == "directory"]

    # Get mount points if we need to skip remote filesystems
    mount_points = _get_mount_points() if skip_remote else {}

    if skip_remote and mount_points:
        print("Skipping network and virtual filesystems (use --include-remote to scan all)\n")

    print("Scanning for Indicators of Compromise (IoCs)...\n")
    for dirpath, dirnames, filenames in os.walk(scan_root):
        # Check if we should skip this directory
        if _should_skip_path(dirpath, mount_points, skip_remote):
            # Don't descend into subdirectories
            dirnames[:] = []
            continue

        dir_finding = _scan_host_path_iocs(host_dir_iocs, dirpath)
        if dir_finding:
            yield dir_finding

        for filename in filenames:
            filepath = os.path.join(dirpath, filename)

            pkg_finding = _scan_package_json(malicious_packages, filepath)
            if pkg_finding:
                yield pkg_finding

            file_finding = _scan_host_path_iocs(host_file_iocs, filepath)
            if file_finding:
                yield file_finding


def main():
    """main entrypoint to the script"""
    parser = argparse.ArgumentParser(
        description='Scan for Shai-Hulud affected NPM packages and IoCs',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        'scan_path',
        nargs='?',
        default='/',
        help='Directory to scan (default: /)'
    )
    parser.add_argument(
        '--include-remote',
        action='store_true',
        help='Include network and virtual filesystems in scan (by default they are skipped)'
    )

    args = parser.parse_args()
    scan_root = os.path.abspath(args.scan_path)
    skip_remote = not args.include_remote

    findings = _scan_for_iocs(scan_root, skip_remote=skip_remote)
    found = False
    for finding in findings:
        if not found:
            found = True
            print(
                "\033[1m[\033[91mWARNING\033[0m\033[1m] Malicious Package IoC(s) Found:\033[0m\n"
            )

        print("- Finding:", finding["finding"])
        print("  Context:", finding["context"])
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
