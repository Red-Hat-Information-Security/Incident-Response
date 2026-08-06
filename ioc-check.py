#!/usr/bin/env python3
"""
USAGE
    python3 ioc-check.py [scan_root]
    python3 ioc-check.py --git-repo git@github.com:owner/repo.git [...]
    python3 ioc-check.py --github-org myorg [myorg2 ...]

DESCRIPTION
    Walk the filesystem and/or scan git repositories for known indicators of
    compromise (IoCs).

NOTES
    Package findings are displayed using the PURL[1] syntax.

    [1]: https://github.com/package-url/purl-spec
"""

import argparse
import csv
import fnmatch
import io
import json
import logging
import multiprocessing
import os
import re
import socket
import subprocess
import sys
import time

from urllib import request
from urllib.parse import quote, unquote

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
            return [], {}

        print("Loading RHIS Host IoC db...")
        response_text = io.TextIOWrapper(response, encoding="UTF-8")
        iocs = list(csv.DictReader(response_text))
        path_types = {"directory", "file"}

        git_file_iocs = {}
        for ioc in iocs:
            if ioc["ioc_type"] == "file":
                raw = ioc["ioc_value"]
                content_regex_str = None
                parts = raw.split(":", 1)
                if len(parts) == 2:
                    raw = parts[0]
                    content_regex_str = parts[1]
                if raw.startswith("**/"):
                    path = raw[3:]
                    if "*" not in path and "?" not in path:
                        if path in git_file_iocs:
                            existing = git_file_iocs[path]
                            if existing["content_regex"] is not None:
                                if content_regex_str is None:
                                    existing["content_regex"] = None
                                else:
                                    existing["content_regex"] += "|" + content_regex_str
                        else:
                            git_file_iocs[path] = {
                                "content_regex": content_regex_str,
                                "campaign_name": ioc["campaign_name"],
                                "ioc_description": ioc["ioc_description"],
                            }

        for info in git_file_iocs.values():
            if info["content_regex"] is not None:
                info["content_regex"] = re.compile(info["content_regex"])

        for ioc in iocs:
            if ioc["ioc_type"] == "file_regex":
                raw_value = ioc["ioc_value"]
                content_regex = None

                parts = raw_value.split(":", 1)
                if len(parts) == 2:
                    raw_value = parts[0]
                    content_regex = re.compile(parts[1])

                ioc["ioc_value"] = re.compile(raw_value)
                ioc["content_regex"] = content_regex

            elif ioc["ioc_type"] in path_types:
                raw_value = ioc["ioc_value"]
                content_regex = None

                parts = raw_value.split(":", 1)
                if len(parts) == 2:
                    raw_value = parts[0]
                    content_regex = re.compile(parts[1])

                glob_pattern = os.path.expanduser(os.path.expandvars(raw_value))
                regex_pattern = fnmatch.translate(glob_pattern)
                if "**" in glob_pattern:
                    regex_pattern = regex_pattern.replace(
                        fnmatch.translate("*")[: -len("$")],
                        ".*",
                    )
                ioc["ioc_value"] = re.compile(regex_pattern)
                ioc["content_regex"] = content_regex

        return iocs, git_file_iocs


def _check_host_iocs(host_path_iocs, path):
    for ioc in host_path_iocs:
        if ioc["ioc_value"].match(path):
            content_regex = ioc.get("content_regex")
            if content_regex:
                try:
                    with open(path, encoding="UTF-8", errors="ignore") as f:
                        if not content_regex.search(f.read()):
                            continue
                except Exception:
                    continue

            return {
                "path": path,
                "finding": "Host IoC: " + ioc["ioc_description"],
                "notes": "Campaign: " + ioc["campaign_name"],
            }

    return None


def _check_lockfile(filepath, malicious_packages):
    try:
        with open(filepath, encoding="UTF-8", errors="ignore") as f:
            lockfile = json.load(f)
    except Exception:
        return

    # v2/v3
    for key, info in lockfile.get("packages", {}).items():
        if not key:
            continue
        if not isinstance(info, dict):
            logging.warning("Deformed file in %s (key %r): expected dict, got %s", filepath, key, type(info).__name__)
            continue
        name = key.rsplit("node_modules/", 1)[-1]
        version = info.get("version", "")
        if name and version:
            purl = _new_purl("npm", name, version)
            if purl in malicious_packages:
                yield {
                    "path": filepath,
                    "finding": "Lockfile referencing compromised package: " + purl,
                    "notes": malicious_packages[purl],
                }

    # v1
    def check_deps(deps):
        for name, info in deps.items():
            if not isinstance(info, dict):
                logging.warning("Deformed file in %s (dep %r): expected dict, got %s", filepath, name, type(info).__name__)
                continue
            version = info.get("version", "")
            if name and version:
                purl = _new_purl("npm", name, version)
                if purl in malicious_packages:
                    yield {
                        "path": filepath,
                        "finding": "Lockfile referencing compromised package: " + purl,
                        "notes": malicious_packages[purl],
                    }
            yield from check_deps(info.get("dependencies", {}))

    yield from check_deps(lockfile.get("dependencies", {}))


def _parse_npm_cache_entry(key):
    if not key.endswith(".tgz"):
        return None

    http_idx = key.rfind("https://")
    if http_idx < 0:
        http_idx = key.rfind("http://")
    if http_idx < 0:
        return None
    url = key[http_idx:]

    sep_idx = url.find("/-/")
    if sep_idx < 0:
        return None

    scheme_end = url.find("://")
    if scheme_end < 0:
        return None
    after_scheme = url[scheme_end + 3:]
    host_end = after_scheme.find("/")
    if host_end < 0:
        return None

    name_part = after_scheme[host_end + 1:after_scheme.find("/-/")]
    name = unquote(name_part).lower()

    tarball = url[sep_idx + 3:]
    unscoped = name.rsplit("/", 1)[-1]

    prefix = unscoped + "-"
    if not tarball.startswith(prefix):
        return None
    version = tarball[len(prefix):-4]

    if not version or not version[0].isdigit():
        return None

    return name, version


def _check_npm_cache_dir(index_dir, malicious_packages):
    for dirpath, _dirnames, filenames in os.walk(index_dir):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            try:
                with open(filepath, encoding="UTF-8", errors="ignore") as f:
                    last_line = None
                    for line in f:
                        stripped = line.strip()
                        if stripped:
                            last_line = stripped
                    if not last_line:
                        continue

                parts = last_line.split("\t", 1)
                if len(parts) != 2:
                    continue

                entry = json.loads(parts[1])
                parsed = _parse_npm_cache_entry(entry.get("key", ""))
                if not parsed:
                    continue

                name, version = parsed
                purl = _new_purl("npm", name, version)
                if purl in malicious_packages:
                    yield {
                        "path": filepath,
                        "finding": "Malicious Package (npm cache): " + purl,
                        "notes": malicious_packages[purl],
                    }
            except Exception:
                continue


def _check_iocs(scan_root, malicious_packages, host_iocs):
    host_file_iocs = [ioc for ioc in host_iocs if ioc["ioc_type"] in {"file", "file_regex"}]
    host_dir_iocs = [ioc for ioc in host_iocs if ioc["ioc_type"] == "directory"]

    print("Scanning for Indicators of Compromise (IoCs)...\n")
    for dirpath, dirnames, filenames in os.walk(scan_root):
        dir_finding = _check_host_iocs(host_dir_iocs, dirpath)
        if dir_finding:
            yield dir_finding

        if dirpath.endswith("/_cacache") and "index-v5" in dirnames:
            index_dir = os.path.join(dirpath, "index-v5")
            yield from _check_npm_cache_dir(index_dir, malicious_packages)
            dirnames.remove("index-v5")

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

            if filename == "package-lock.json":
                yield from _check_lockfile(filepath, malicious_packages)

            file_finding = _check_host_iocs(host_file_iocs, filepath)
            if file_finding:
                yield file_finding


valid_repo_hosts = set()


def check_host(host):
    logging.info("checking repo host: repo_host=%s", host)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            result = s.connect_ex((host, 22))
            return result == 0
    except Exception as e:
        logging.error("repo host check failed: repo_host=%s error=%s", host, e)
        return False


def parse_repo_info(clone_url):
    repo_host = None
    repo_name = None

    if clone_url.startswith("https://") or clone_url.startswith("http://"):
        parts = clone_url.split("//", 1)[1].split("/", 1)
        repo_host = parts[0].lower()
        repo_name = parts[1].removesuffix(".git") if len(parts) > 1 else None
    elif ":" in clone_url and "@" in clone_url:
        host_part = clone_url.split("@", 1)[1].split(":", 1)
        repo_host = host_part[0].lower()
        repo_name = host_part[1].removesuffix(".git") if len(host_part) > 1 else None
    else:
        logging.error("invalid clone url: %s", clone_url)
        return None, None

    if not repo_name or not repo_host:
        return None, None

    if repo_host not in valid_repo_hosts:
        if check_host(repo_host):
            valid_repo_hosts.add(repo_host)
        else:
            logging.error("invalid repo host provided: repo_host=%s", repo_host)
            return None, None

    return repo_host, repo_name


def read_repo_file(repo_path, commit_id, file_path):
    try:
        return subprocess.check_output(
            ["git", "-C", repo_path, "show", f"{commit_id}:{file_path}"],
            text=True,
        )
    except subprocess.CalledProcessError as e:
        logging.error("read repo file failed: repo_path=%s commit=%s file_path=%s error=%s", repo_path, commit_id, file_path, e)
        return ""


def check_repo(args):
    clone_url, file_iocs = args
    results = []
    repo_host, repo_name = parse_repo_info(clone_url)
    if not repo_name or not repo_host:
        return results

    logging.info("checking repo: repo_host=%s repo_name=%s", repo_host, repo_name)
    repo_path = f"repos/{repo_host}/{repo_name}.git"

    if not os.path.exists(repo_path):
        try:
            logging.info("cloning repo: repo_host=%s repo_name=%s", repo_host, repo_name)
            subprocess.run(
                [
                    "git", "clone", "--mirror", "--filter=blob:none",
                    clone_url, repo_path,
                ],
                check=True,
            )
        except subprocess.CalledProcessError as e:
            logging.error("clone failed: repo_host=%s repo_name=%s error=%s", repo_host, repo_name, e)
            return results
    else:
        try:
            logging.info("fetching updates: repo_host=%s repo_name=%s", repo_host, repo_name)
            subprocess.run(
                ["git", "-C", repo_path, "fetch", "--all", "--filter=blob:none"],
                check=True,
            )
        except subprocess.CalledProcessError as e:
            logging.error("fetch failed: repo_host=%s repo_name=%s error=%s", repo_host, repo_name, e)

    try:
        cat_file_out = subprocess.check_output(
            [
                "git", "-C", repo_path, "cat-file",
                "--batch-all-objects",
                "--batch-check=%(objectname) %(objecttype)",
            ],
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        logging.error("commit lookup failed: repo_host=%s repo_name=%s error=%s", repo_host, repo_name, e)
        return results

    commits = [
        line[:40] for line in cat_file_out.splitlines() if line.endswith(" commit")
    ]

    if not commits:
        return results

    queries = [
        (commit_id, ioc_path)
        for commit_id in commits
        for ioc_path in file_iocs
    ]

    batch_size = 50000
    for i in range(0, len(queries), batch_size):
        batch = queries[i : i + batch_size]
        batch_input = "\n".join(f"{commit}:{path}" for commit, path in batch) + "\n"

        try:
            batch_output = subprocess.check_output(
                ["git", "-C", repo_path, "cat-file", "--batch-check"],
                stderr=subprocess.DEVNULL,
                input=batch_input,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            logging.error("cat-file failed for batch: repo_host=%s repo_name=%s batch=%d error=%s", repo_host, repo_name, i, e)
            continue

        for (commit_id, file_path), out_line in zip(batch, batch_output.splitlines()):
            if out_line.endswith(" missing"):
                continue

            parts = out_line.split()
            if not (len(parts) >= 2 and parts[1] == "blob"):
                continue

            ioc_info = file_iocs[file_path]
            content_regex = ioc_info["content_regex"]
            if content_regex is not None:
                logging.info("inspecting file: repo_host=%s repo_name=%s commit=%s file_path=%s", repo_host, repo_name, commit_id, file_path)
                content = read_repo_file(repo_path, commit_id, file_path)
                if not content_regex.search(content):
                    logging.info("ignoring file: repo_host=%s repo_name=%s commit=%s file_path=%s", repo_host, repo_name, commit_id, file_path)
                    continue

            url = f"https://{repo_host}/{repo_name}/blob/{commit_id}/{file_path}"
            results.append({
                "path": url,
                "finding": f"Git Repo IoC: {file_path}",
                "notes": (
                    f"Campaign: {ioc_info['campaign_name']}"
                    f" — repo: {repo_name} commit: {commit_id[:12]}"
                ),
            })

    return results


def _list_github_org_repos(org_name):
    token = os.environ.get("GITHUB_TOKEN")
    repos = []
    page = 1

    while True:
        url = (
            f"https://api.github.com/orgs/{org_name}/repos"
            f"?per_page=100&page={page}&type=all"
        )
        req = request.Request(url)
        req.add_header("Accept", "application/vnd.github+json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with request.urlopen(req) as response:
                data = json.loads(response.read())
                if not data:
                    break
                repos.extend(r["clone_url"] for r in data)
                page += 1
        except Exception as e:
            print(f"ERROR: Failed to list repos for org '{org_name}': {e}")
            if not token:
                print("Hint: Set GITHUB_TOKEN environment variable for private repo access")
            break

    return repos


def _scan_git_repos(repo_list, file_iocs):
    process_count = max(1, multiprocessing.cpu_count() // 2)
    logging.info("starting scan processes: process_count=%d", process_count)

    args_list = [(repo, file_iocs) for repo in repo_list]

    with multiprocessing.Pool(process_count) as p:
        for results in p.imap_unordered(check_repo, args_list):
            yield from results


def _parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Scan for indicators of compromise on the host filesystem and/or in git repositories."
        ),
    )
    parser.add_argument(
        "scan_root",
        nargs="?",
        default=None,
        help="Root directory for host filesystem scan (default: /)",
    )
    parser.add_argument(
        "--git-repo",
        nargs="+",
        metavar="REPO",
        help="Git repositories to scan (clone URL, e.g. git@github.com:owner/repo.git)",
    )
    parser.add_argument(
        "--github-org",
        nargs="+",
        metavar="ORG",
        help="GitHub organizations — scan all repos under each org",
    )
    return parser.parse_args()


def main():
    args = _parse_args()

    run_host_scan = args.scan_root is not None or (
        not args.git_repo and not args.github_org
    )
    run_git_scan = bool(args.git_repo or args.github_org)

    if run_git_scan:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
        )

    malicious_packages = _load_malicious_packages()

    host_iocs = None
    git_file_iocs = None
    if run_host_scan or run_git_scan:
        host_iocs, git_file_iocs = _load_malicious_package_host_iocs()

    found = False

    if run_host_scan:
        scan_root = os.path.abspath(args.scan_root or "/")

        for finding in _check_iocs(scan_root, malicious_packages, host_iocs):
            if not found:
                found = True
                print(
                    "\033[1m[\033[91mWARNING\033[0m\033[1m] Malicious Package IoC(s) Found:\033[0m\n"
                )

            print("- Finding:", finding["finding"])
            print("  Notes:", finding["notes"])
            print("  Location:", finding["path"])
            print()

    if run_git_scan:
        repo_list = list(args.git_repo or [])
        for org in args.github_org or []:
            print(f"Listing repos for org '{org}'...")
            org_repos = _list_github_org_repos(org)
            print(f"Found {len(org_repos)} repos in '{org}'")
            repo_list.extend(org_repos)

        if repo_list:
            print(f"\nScanning {len(repo_list)} git repo(s) for IoCs...\n")
            for finding in _scan_git_repos(repo_list, git_file_iocs):
                if not found:
                    found = True
                    print(
                        "\033[1m[\033[91mWARNING\033[0m\033[1m] IoC(s) Found:\033[0m\n"
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
