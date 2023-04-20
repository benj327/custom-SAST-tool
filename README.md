# GitHub Security Analyzer

This tool is designed to analyze a GitHub repository for security vulnerabilities in Python code and dependencies. It uses the Bandit static code analysis tool to scan Python files and GitHub's GraphQL API to fetch dependency vulnerability alerts.

## Installation

1. Clone this repository:

```git clone https://github.com/benj327/custom-SAST-tool```

2. Change to the project directory:

```cd custom-SAST-tool```

3. Create a virtual environment and activate it:

For Unix or macOS:

```python3 -m venv venv
source venv/bin/activate```

For Windows:

```python -m venv venv
.\venv\Scripts\activate```

4. Install the required dependencies:

```pip install -r requirements.txt```

5. Create a `config.py` file with your GitHub API token:

```apikey = "your-github-api-token"```

## Usage

Run the script with the following command:

```python main.py [repo_url] --python```

Replace [repo_url] with the URL of the GitHub repository you want to analyze.

Example:

```python main.py https://github.com/yourusername/your-repo --python```

This will analyze the specified repository and display the security issues found in the Python code and dependencies.
