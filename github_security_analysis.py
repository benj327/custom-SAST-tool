import os
import requests
import json
import base64
import io
import tempfile
import subprocess
import argparse
from config import apikey

GITHUB_TOKEN = apikey

def fetch_security_vulnerabilities(owner, repo):
    query = """
    query($owner: String!, $repo: String!, $cursor: String) {
        repository(owner: $owner, name: $repo) {
            vulnerabilityAlerts(first: 100, after: $cursor) {
                edges {
                    node {
                        securityVulnerability {
                            package {
                                name
                            }
                            severity
                            advisory {
                                description
                            }
                        }
                    }
                }
                pageInfo {
                    endCursor
                    hasNextPage
                }
            }
        }
    }
    """

    variables = {"owner": owner, "repo": repo}

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Content-Type": "application/json",
    }

    response = requests.post(
        "https://api.github.com/graphql",
        headers=headers,
        json={"query": query, "variables": json.dumps(variables)},
    )

    response.raise_for_status()

    return response.json()


def download_python_files_from_repo(owner, repo):
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents"

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
    }

    files = []
    directories_to_process = ["/"]

    while directories_to_process:
        current_dir = directories_to_process.pop()
        response = requests.get(api_url + current_dir, headers=headers)
        response.raise_for_status()
        items = response.json()

        for item in items:
            if item["type"] == "file":
                if item["path"].endswith(".py"):
                    file_url = item["download_url"]
                    response = requests.get(file_url)
                    file_content = response.text
                    files.append((item["path"], io.StringIO(file_content)))
            elif item["type"] == "dir":
                directories_to_process.append(item["path"])

    return files

def run_bandit_on_files(files):
    with tempfile.TemporaryDirectory() as temp_dir:
        for file_path, file_content in files:
            temp_file_path = os.path.join(temp_dir, file_path)
            os.makedirs(os.path.dirname(temp_file_path), exist_ok=True)

            with open(temp_file_path, "w") as temp_file:
                temp_file.write(file_content.read())

        bandit_executable = "bandit"

        bandit_command = [bandit_executable, "-r", temp_dir, "-f", "json", "-o", "results.json"]

        result = subprocess.run(bandit_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        print("Bandit output:")
        print(result.stdout)
        print("Bandit error output:")
        print(result.stderr)

        if result.returncode not in [0, 1]:
            raise Exception("Bandit failed")

        try:
            with open("results.json", "r") as results_file:
                results_data = results_file.read()
                if not results_data.strip():
                    return json.dumps({"results": []})
        except FileNotFoundError:
            raise

        os.remove("results.json")
        return results_data

def analyze_github_repository(owner, repo):
    # Download Python files from the repository
    files = download_python_files_from_repo(owner, repo)

    # Run Bandit on the downloaded files
    scanner_results = run_bandit_on_files(files)

    scanner_data = json.loads(scanner_results)
    print("Python code scanning results:\n")
    for issue in scanner_data["results"]:
        print(f"File: {issue['filename']}\nLine: {issue['line_number']}\nIssue: {issue['issue_text']}\n")

    # Fetch dependency vulnerability alerts
    vulnerabilities = fetch_security_vulnerabilities(owner, repo)
    vulnerability_alerts = vulnerabilities["data"]["repository"]["vulnerabilityAlerts"]["edges"]

    print("\nDependency vulnerability alerts:\n")
    for alert in vulnerability_alerts:
        node = alert["node"]
        package_name = node["securityVulnerability"]["package"]["name"]
        package_name = node["securityVulnerability"]["package"]["name"]
        severity = node["securityVulnerability"]["severity"]
        description = node["securityVulnerability"]["advisory"]["description"]

        print(f"Package: {package_name}\nSeverity: {severity}\nDescription: {description}\n")

def parse_repo_url(repo_url):
    repo_path = repo_url.replace("https://github.com/", "")
    owner, repo = repo_path.strip("/").split("/", 1)
    return owner, repo

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze a GitHub repository for security vulnerabilities.")
    parser.add_argument("repo_url", help="URL of the GitHub repository to analyze")

    args = parser.parse_args()

    owner, repo = parse_repo_url(args.repo_url)
    analyze_github_repository(owner, repo)
