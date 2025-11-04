# AWS_Tooling - ![Version](https://img.shields.io/badge/version-1.0.0-blue)

**AWS_Tooling** is a collection of utility scripts designed to simplify and automate various AWS account management and security tasks. The repository aims to provide modular scripts for auditing, enumeration, and general AWS operational tasks.  

The first script, **EnumerateSchemaVersions.sh**, allows you to enumerate policies across multiple AWS services and verify that they are using the correct AWS policy schema version.

---

## Features

- **Policy Enumeration:** Enumerates policies for IAM, S3, SNS, SQS, Lambda, KMS, Secrets Manager, EventBridge, API Gateway, CloudWatch Logs, and Step Functions.  
- **Schema Version Audit:** Checks each policy against a user-defined latest schema version and flags outdated or missing versions.  
- **Verbose Mode:** Optional `-v` flag to display detailed console output, including compliant policies and confirmation of valid credentials.  
- **Profile Support:** Supports default or custom AWS CLI profiles.  
- **User-Friendly Output:** Color-coded terminal warnings and CSV export for audit reporting.  
- **Pre-Flight AWS Check:** Validates AWS CLI authentication before running the audit.

---

## Services Audited

| Service | Audited |
|---------|---------|
| IAM | ✅ |
| S3 | ✅ |
| SNS | ✅ |
| SQS | ✅ |
| Lambda | ✅ |
| KMS | ✅ |
| Secrets Manager | ✅ |
| EventBridge | ✅ |
| API Gateway | ✅ |
| CloudWatch Logs | ✅ |
| Step Functions | ✅ |

---

## Prerequisites

- Bash 4+  
- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html) configured with proper credentials.  
- [jq](https://stedolan.github.io/jq/) installed for JSON parsing.  
- AWS IAM permissions sufficient to list and query policies for IAM, S3, SNS, SQS, Lambda, KMS, and Secrets Manager.

---

## Installation

1. **Clone the Repository:**

```bash
git clone https://github.com/JackMarsden/AWS_Tooling
```

2. **Navigate to the Directory:**

```bash
cd AWS_Tooling
```

3. **Make the Script Executable:**

```bash
chmod +x EnumerateSchemaVersions.sh
```

---

## Usage

```bash
./EnumerateSchemaVersions.sh --latestSchemaVersion "2012-10-17" [--profile <aws_profile_name>] [--v]
```

### Parameters

| Flag | Description | Required |
|------|-------------|----------|
| `--latestSchemaVersion` | The latest AWS policy schema version to compare against (e.g., "2012-10-17"). | ✅ Yes |
| `--profile` | Optional AWS CLI profile to use. Defaults to `default`. | ❌ No |
| `--v` | Optional verbose mode for detailed console output. | ❌ No |

### Examples

# Using default AWS CLI profile
```bash
./EnumerateSchemaVersions.sh --latestSchemaVersion "2012-10-17"
```

# Using a specific profile
```bash
./EnumerateSchemaVersions.sh --latestSchemaVersion "2012-10-17" --profile MyAccount
```

# Using verbose mode
```bash
./EnumerateSchemaVersions.sh --latestSchemaVersion "2012-10-17" --v
```

---

## Output

- **Terminal:** Displays warnings for missing or outdated policy schema versions. Verbose mode shows compliant policies and credential validation 
- **CSV:** Saves a complete audit file (e.g., `aws_policy_schema_audit_YYYYMMDD_HHMMSS.csv`) with the following columns:

Service,Resource,PolicyNameOrID,PolicyVersion,Status

- Color-coded output:
  - 🔴 Red: Errors or Outdated schema versionmissing schema version  
  - 🟡 Yellow: missing schema version  
  - 🟢 Green: Up-to-date  

---

## Notes

- The `--latestSchemaVersion` flag is **mandatory**. AWS IAM policy schema versions documentation can be found [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_version.html).  
- The script is modular, allowing you to expand it to additional AWS services in future releases.  
- If no `--profile` is specified, the script uses the default AWS CLI profile.
- Verbose mode (`--v`) is optional but recommended for troubleshooting or auditing purposes.  
