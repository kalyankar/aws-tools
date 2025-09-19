# S3 HTTP Deny Policy Script with CSV Input

This script authenticates directly to a shared AWS account using environment variables, assumes cross-account roles to access target accounts, and updates S3 bucket policies to deny HTTP requests (enforce HTTPS only).

## Features

- **CSV Input**: Reads account information from a CSV file
- **Role Assumption**: Assumes cross-account roles to access different AWS accounts
- **S3 Policy Management**: Checks and updates S3 bucket policies to deny HTTP requests
- **Comprehensive Logging**: Logs all activities with timestamps
- **Policy Backup**: Automatically backs up existing policies before modification
- **Dry Run Mode**: Perform all AWS operations (authentication, role assumption, bucket listing, policy retrieval) but skip policy updates
- **Error Handling**: Robust error handling with detailed reporting

## Prerequisites

1. **AWS Credentials**: Configure AWS credentials for the shared account using environment variables
2. **Shared Account Access**: Direct access to the shared account (no role assumption needed)
3. **Cross-Account Roles**: Each target account must have a role that can be assumed by the shared account
4. **Required Permissions**: 
   - **Shared account credentials**: `sts:AssumeRole` to assume target account roles
   - **Target account roles**: 
     - `s3:ListBucket` - to list S3 buckets
     - `s3:GetBucketPolicy` - to read bucket policies
     - `s3:PutBucketPolicy` - to update bucket policies

## Installation

1. Install required dependencies:
```bash
pip install -r requirements.txt
```

2. Ensure AWS credentials are configured for the shared account:
```bash
# Set environment variables for shared account:
export AWS_ACCESS_KEY_ID=your_shared_account_access_key
export AWS_SECRET_ACCESS_KEY=your_shared_account_secret_key
export AWS_SESSION_TOKEN=your_session_token  # Optional, for temporary credentials
# OR use AWS CLI:
aws configure --profile shared-account
```

## CSV File Format

Create a CSV file with the following columns:

| Column | Required | Description |
|--------|----------|-------------|
| `target_account_id` | Yes | AWS Account ID of the target account (12 digits) |
| `target_role_arn` | Yes | ARN of the role to assume in the target account |
| `target_role_session_name` | No | Name for the target account role session (defaults to timestamped name) |

### Example CSV File (`accounts.csv`):

```csv
target_account_id,target_role_arn,target_role_session_name
123456789012,arn:aws:iam::123456789012:role/CrossAccountRole,TargetSession1
987654321098,arn:aws:iam::987654321098:role/CrossAccountRole,TargetSession2
555666777888,arn:aws:iam::555666777888:role/CrossAccountRole,TargetSession3
```

## Usage

### Basic Usage

```bash
python httpDeny_all_accounts.py accounts.csv
```

### With Custom Region

```bash
python httpDeny_all_accounts.py accounts.csv --region us-west-2
```

### Dry Run Mode (Recommended First)

```bash
python http_deny.py accounts.csv --dry-run
```

**Note**: Dry run mode performs all AWS operations (authentication, role assumption, bucket listing, policy retrieval) but skips the actual policy updates. This gives you a realistic preview of what the script will do.

### Full Command with Options

```bash
python http_deny.py accounts.csv --region us-east-1 --dry-run
```

## Command Line Arguments

- `csv_file` (required): Path to CSV file containing account information
- `--region`: AWS region (default: us-east-1)
- `--dry-run`: Perform all AWS operations except policy updates

## What the Script Does

1. **Reads CSV**: Parses the CSV file to get target account information
2. **Authenticates to Shared Account**: Uses environment variables to authenticate directly to the shared account
3. **Assumes Target Roles**: For each target account, assumes the specified role from the shared account
4. **Lists Buckets**: Gets all S3 buckets in each target account
5. **Checks Policies**: Examines existing bucket policies
6. **Backs Up Policies**: Saves current policies to backup files
7. **Updates Policies**: Adds HTTP deny statements to bucket policies
8. **Logs Activities**: Records all actions and results

## S3 Policy Statement Added

The script adds the following policy statement to deny HTTP requests:

```json
{
  "Sid": "DenyHttpRequests",
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:*",
  "Resource": [
    "arn:aws:s3:::bucket-name",
    "arn:aws:s3:::bucket-name/*"
  ],
  "Condition": {
    "StringEquals": {
      "aws:SecureTransport": "false"
    }
  }
}
```

## Output and Logging

### Console Output
- Real-time progress updates
- Success/failure indicators (✓/✗)
- Summary statistics
- Error messages

### Log Files
- Location: `logs/s3_http_deny_csv_YYYYMMDD_HHMMSS.log`
- Contains detailed logging of all activities
- Includes timestamps and log levels

### Policy Backups
- Location: `s3_policy_backups_YYYYMMDD_HHMMSS/`
- Individual JSON files for each bucket policy
- Format: `{account_id}_{bucket_name}_policy_backup_{timestamp}.json`

## Example Output

```
Starting S3 HTTP Deny Policy Update
==================================================
Reading target accounts from CSV file...
Read 3 target accounts from CSV file
Policy backups will be saved to: s3_policy_backups_20241201_143022
Found 3 target accounts to process
✓ Authenticated to shared account: 111111111111

Processing target account: 123456789012
Target Role ARN: arn:aws:iam::123456789012:role/CrossAccountRole
✓ Successfully assumed role in account: 123456789012
Found 5 S3 buckets in account 123456789012
✓ Retrieved policy for my-bucket-1
✓ Updated bucket policy for my-bucket-1 to deny HTTP requests
✓ Saved policy backup to: s3_policy_backups_20241201_143022/123456789012_my-bucket-1_policy_backup_20241201_143022.json
✓ Retrieved policy for my-bucket-2
✓ Bucket my-bucket-2 already has HTTP deny policy

==================================================
SUMMARY
==================================================
Total accounts processed: 3
Successful accounts: 3
Total buckets found: 15
Total successful policy updates: 12
```

## Error Handling

The script handles various error scenarios:

- **CSV File Issues**: Missing file, invalid format, missing columns
- **Role Assumption Failures**: Invalid role ARN, insufficient permissions
- **S3 Access Issues**: Bucket access denied, policy read/write failures
- **Network Issues**: Connection timeouts, service unavailability

## Security Considerations

1. **Least Privilege**: Ensure assumed roles have minimal required permissions
2. **Policy Backups**: Always review backup files before running
3. **Dry Run First**: Always test with `--dry-run` before actual execution
4. **Audit Logs**: Review log files for security compliance
5. **Role Trust**: Ensure role trust policies are properly configured

## Troubleshooting

### Common Issues

1. **"Access Denied" when authenticating to shared account**
   - Check AWS credentials are set correctly in environment variables
   - Verify credentials have access to the shared account
   - Ensure credentials are not expired

2. **"Access Denied" when assuming target account role**
   - Check target account role ARN format
   - Verify trust policy allows the shared account to assume it
   - Ensure the shared account has `sts:AssumeRole` permission

3. **"No such bucket policy" errors**
   - This is normal for buckets without existing policies
   - The script will create a new policy

4. **CSV parsing errors**
   - Check CSV format and encoding
   - Ensure required columns are present (target_account_id, target_role_arn)
   - Verify no empty rows with missing data

5. **Permission errors on S3 operations**
   - Verify target account role has required S3 permissions
   - Check bucket policies don't deny access

### Debug Mode

For more detailed logging, you can modify the logging level in the script:

```python
logging.basicConfig(level=logging.DEBUG, ...)
```

## Best Practices

1. **Test First**: Always run with `--dry-run` first (performs all operations except policy updates)
2. **Backup Review**: Review policy backups before making changes
3. **Staged Rollout**: Test on a few accounts before full deployment
4. **Monitor Logs**: Watch for errors and unexpected behavior
5. **Document Changes**: Keep track of which accounts were processed

## Support

For issues or questions:
1. Check the log files for detailed error information
2. Verify AWS credentials and permissions
3. Test with a single account first
4. Review the dry-run output for expected behavior
