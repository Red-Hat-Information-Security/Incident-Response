#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory

if not shutil.which("git"):
    print("=" * 79)
    print("\nERROR: This script requires the git command to be installed.")
    print(
        "\nHere are steps for installing git:",
        "https://github.com/git-guides/install-git\n",
    )
    print("=" * 79)
    sys.exit(1)


disclaimer = """
===============================================================================
DISCLAIMER
-------------------------------------------------------------------------------
This script can miss things. It's meant to be a basic check against packages
in https://github.com/ossf/malicious-packages with specific versions listed.
===============================================================================
"""


def load_json_file_path(json_file_path):
    try:
        with open(json_file_path, encoding="UTF-8") as json_file:
            return json.load(json_file)
    except Exception:
        return {}


def load_package_version(package_json_path):
    try:
        package_json_data = load_json_file_path(package_json_path)
        name = package_json_data["name"].lower()
        version = package_json_data["version"].lower()

        if name and version:
            return f"{name}@{version}"
    except Exception:
        pass

    return None


def load_malicious_npm_package_set():
    with TemporaryDirectory() as tmpdir:
        print("Fetching malicious package db...")
        subprocess.run(
            [
                "git",
                "clone",
                "--depth=1",
                "https://github.com/ossf/malicious-packages.git",
                tmpdir,
            ],
            capture_output=True,
            check=True,
            shell=False,
        )

        print("Loading malicious package set...")
        npm_packages_dir = os.path.join(tmpdir, "osv/malicious/npm")
        return {
            f"{affected['package']['name']}@{version}".lower()
            for dirpath, dirnames, filenames in os.walk(npm_packages_dir)
            for filename in filenames
            if filename.endswith(".json")
            for affected in load_json_file_path(os.path.join(dirpath, filename)).get(
                "affected", []
            )
            for version in affected.get("versions", [])
        }


def main():
    malicious_packages = load_malicious_npm_package_set()
    package_json_paths = (
        os.path.join(dirpath, filename)
        for dirpath, dirnames, filenames in os.walk("/")
        for filename in filenames
        if filename == "package.json"
    )

    print("Scanning installed npm packages...")
    found = False
    for package_json_path in package_json_paths:
        package_version = load_package_version(package_json_path)
        if not package_version:
            continue

        if package_version in malicious_packages:
            print(package_version, "->", package_json_path)
            found = True

    if not found:
        print("No malicious packages found")


if __name__ == "__main__":
    print(disclaimer)
    main()
