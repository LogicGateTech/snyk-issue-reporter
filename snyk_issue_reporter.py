import sys
import re

from snyk.client import SnykClient


def parse_command_line_arguments():
    if len(sys.argv) != 4:
        print("Usage: python snyk_issue_reporter.py <snyk_client_token> <organization_id> <project_id>")
        sys.exit(1)
    return sys.argv[1], sys.argv[2], sys.argv[3]

def extract_issue_count(pattern, content):
    match = re.search(pattern, content)
    return int(match.group(1)) if match else 0

def read_issue_counts_from_file(file_path):
    issue_patterns = {
        "high": r'(\d+) \[High\]',
        "medium": r'(\d+) \[Medium\]',
        "low": r'(\d+) \[Low\]'
    }

    counts = {}

    with open(file_path, 'r') as file:
        content = file.read()
        counts = {issue: extract_issue_count(pattern, content) for issue, pattern in issue_patterns.items()}

    return counts

def get_snyk_project(client_token, organization_id, project_id):
    client = SnykClient(client_token)
    org = client.organizations.get(organization_id)
    return org.projects.get(project_id)

def get_project_counts(snyk_proj):
    snyk_code_issues = snyk_proj.issueCountsBySeverity
    proj_counts = {
        "high": snyk_code_issues.high,
        "medium": snyk_code_issues.medium,
        "low": snyk_code_issues.low
    }
    return proj_counts

def calculate_ignores(snyk_proj):
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    ignores = snyk_proj.ignores.all()
    for next_issue_id in ignores.keys():
        match = re.search(r'Severity: (\w+)', ignores[next_issue_id][0]['reason'])
        if match:
            severity = match.group(1).lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
    return severity_counts

def compare_counts(text_counts, proj_counts, severity_counts):
    for severity in ["high", "medium", "low"]:
        text_count = text_counts[severity] - severity_counts[severity]
        proj_count = proj_counts[severity]
        if text_count > proj_count:
            sys.exit(f"Failure: {severity.capitalize()} count from snyk code test ({text_count}) is greater than from Project ({proj_count}). Please run snyk code test locally to identify the vulnerabilties added in this MR.")

    print("Success: All severity counts from snyk code test are equal to or less than their corresponding counts from the Project.")

def main():
    snyk_client_token, organization_id, project_id = parse_command_line_arguments()

    snyk_proj = get_snyk_project(snyk_client_token, organization_id, project_id)

    proj_counts = get_project_counts(snyk_proj)
    text_counts = read_issue_counts_from_file('snyk-code-test-output.txt')
    severity_counts = calculate_ignores(snyk_proj)

    compare_counts(text_counts, proj_counts, severity_counts)

if __name__ == "__main__":
    main()
