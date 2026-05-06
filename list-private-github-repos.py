#!/usr/bin/env python3
import requests
import os
import sys

# --- CONFIGURATION ---
# The script will look for an environment variable named 'GITHUB_TOKEN'
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')
API_URL = "https://api.github.com/user/repos"

def list_private_repos():
    # Safety check: Exit if the token is missing
    if not GITHUB_TOKEN:
        print("Error: 'GITHUB_TOKEN' environment variable not set.")
        print("Please set it using: export GITHUB_TOKEN='your_token'")
        sys.exit(1)

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    params = {
        "visibility": "private",
        "per_page": 100, 
        "page": 1
    }

    private_repos = []
    print("Fetching private repositories...\n")

    while True:
        response = requests.get(API_URL, headers=headers, params=params)
        
        if response.status_code != 200:
            print(f"Error: {response.status_code} - {response.text}")
            break
        
        repos = response.json()
        if not repos:
            break
            
        private_repos.extend(repos)
        params["page"] += 1

    if private_repos:
        print(f"Found {len(private_repos)} private repositories:\n")
        for repo in private_repos:
            print(f"- {repo['full_name']} ({repo['html_url']})")
    else:
        print("No private repositories found.")

if __name__ == "__main__":
    list_private_repos()
