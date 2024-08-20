# snyk-issue-reporter
LogicGate's custom solution to utilizing Snyk for branch comparison in Gitlab. The purpose of this project is to provide a way to compare the vulnerabilities of a branch against the main branch. This project is a custom solution to the limitations of Snyk's Gitlab integration.

To run this script, you will need the following tokens and IDs:
- `SNYK_CLIENT_TOKEN` - Your Snyk API token
- `SNYK_ORG` - Your Snyk organization ID
- `SNYK_PROJECT` - Your Snyk project ID

We recommend setting this to environment variables for ease of use.

## Usage
Before running the script, first set up a test output file to compare against by running:
```bash
snyk code test >> snyk-code-test-output.txt
```

Then run the script with the following command:
```bash
python3 snyk_issue_reporter.py $SNYK_CLIENT_TOKEN $SNYK_ORG $SNYK_PROJECT
```

## Output
Given the script runs successfully, the output will be a success message:
> Success: All severity counts from snyk code test are equal to or less than their corresponding counts from the Project.

If a new vulnerability is found, and using a new High priority vulnerability found as an example, expect a message telling you the following:
> Failure: High count from snyk code test (1) is greater than from Project (0). Please run snyk code test locally to identify the vulnerabilties added in this MR.
