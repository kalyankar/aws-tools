#!/usr/bin/env python3
"""
Script to deny HTTP requests on S3 buckets across multiple AWS accounts using CSV input.
Authenticates directly to a shared account using environment variables and assumes the same role in all target accounts.
Reads target account information from a CSV file, assumes roles, and updates S3 bucket policies.
"""

import boto3
import json
import sys
import argparse
import os
import logging
import csv
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError
from typing import List, Dict, Any, Optional

# Global variables for configuration
REGION = 'us-west-2'
DRY_RUN = False
BACKUP_DIR = ""
LOGGER = None


def safe_log(level: str, message: str):
    """Safely log a message, handling cases where LOGGER might be None."""
    if LOGGER:
        if level == 'info':
            LOGGER.info(message)
        elif level == 'warning':
            LOGGER.warning(message)
        elif level == 'error':
            LOGGER.error(message)
        elif level == 'debug':
            LOGGER.debug(message)


def setup_logging(region: str, dry_run: bool) -> str:
    """
    Setup logging configuration and return backup directory path.
    
    Args:
        region (str): AWS region
        dry_run (bool): Whether this is a dry run
        
    Returns:
        str: Path to backup directory
    """
    global LOGGER, BACKUP_DIR
    
    # Create backup directory for policies
    backup_dir = f"s3_policy_backups_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    BACKUP_DIR = backup_dir
    
    # Create logs directory
    logs_dir = "logs"
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    
    # Create log filename with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_filename = f"s3_http_deny_csv_{timestamp}.log"
    log_filepath = os.path.join(logs_dir, log_filename)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filepath),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    LOGGER = logging.getLogger(__name__)
    LOGGER.info(f"Log file created: {log_filepath}")
    LOGGER.info(f"Backup directory: {backup_dir}")
    
    return backup_dir


def create_aws_session(region: str) -> boto3.Session:
    """
    Create AWS session with credentials from environment or default chain.
    
    Args:
        region (str): AWS region
        
    Returns:
        boto3.Session: AWS session
    """
    # Get AWS credentials from environment variables
    aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    aws_session_token = os.getenv('AWS_SESSION_TOKEN')
    
    # Initialize AWS session with credentials from environment
    if aws_access_key_id and aws_secret_access_key:
        session = boto3.Session(
            region_name=region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token
        )
        LOGGER.info("Using AWS credentials from environment variables")
    else:
        # Fall back to default credential chain
        session = boto3.Session(region_name=region)
        LOGGER.info("Using default AWS credential chain")
    
    # Log current identity
    try:
        sts_client = session.client('sts')
        identity = sts_client.get_caller_identity()
        LOGGER.info(f"Using AWS account: {identity['Account']}")
        LOGGER.info(f"Using AWS user/role: {identity['Arn']}")
    except Exception as e:
        LOGGER.warning(f"Could not get caller identity: {e}")
    
    return session


def read_csv_accounts(csv_file_path: str, dry_run: bool) -> List[Dict[str, str]]:
    """
    Read target account information from CSV file.
    
    Expected CSV format:
    target_account_id,target_role_arn,target_role_session_name
    123456789012,arn:aws:iam::123456789012:role/CrossAccountRole,TargetSession1
    987654321098,arn:aws:iam::987654321098:role/CrossAccountRole,TargetSession2
    
    Args:
        csv_file_path (str): Path to the CSV file
        dry_run (bool): Whether this is a dry run
        
    Returns:
        List[Dict[str, str]]: List of target account information dictionaries
    """
    target_accounts = []
    
    try:
        safe_log('info', f"Reading CSV file: {csv_file_path}")
        
        if not os.path.exists(csv_file_path):
            raise FileNotFoundError(f"CSV file not found: {csv_file_path}")
        
        with open(csv_file_path, 'r', newline='', encoding='utf-8') as csvfile:
            # Try to detect delimiter
            sample = csvfile.read(1024)
            csvfile.seek(0)
            sniffer = csv.Sniffer()
            delimiter = sniffer.sniff(sample).delimiter
            
            reader = csv.DictReader(csvfile, delimiter=delimiter)
            
            # Validate required columns
            required_columns = ['target_account_id', 'target_role_arn']
            if not all(col in reader.fieldnames for col in required_columns):
                raise ValueError(f"CSV must contain columns: {required_columns}. Found: {reader.fieldnames}")
            
            for row_num, row in enumerate(reader, start=2):  # Start at 2 because header is row 1
                # Skip empty rows
                if not any(row.values()):
                    continue
                
                # Validate required fields
                if not row.get('target_account_id') or not row.get('target_role_arn'):
                    safe_log('warning', f"Skipping row {row_num}: Missing required fields")
                    continue
                
                # Set default session name if not provided
                if not row.get('target_role_session_name'):
                    row['target_role_session_name'] = f"TargetSession_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                
                # Add target account info
                target_accounts.append({
                    'account_id': row['target_account_id'].strip(),
                    'role_arn': row['target_role_arn'].strip(),
                    'role_session_name': row['target_role_session_name'].strip()
                })
        
        safe_log('info', f"Successfully read {len(target_accounts)} target accounts from CSV file")
        if dry_run:
            print(f"[DRY RUN] Read {len(target_accounts)} target accounts from CSV file")
        else:
            print(f"Read {len(target_accounts)} target accounts from CSV file")
        
        return target_accounts
        
    except Exception as e:
        safe_log('error', f"Error reading CSV file: {e}")
        print(f"Error reading CSV file: {e}")
        raise


def assume_role(session: boto3.Session, role_arn: str, role_session_name: str, region: str, dry_run: bool, external_id: str = None) -> Optional[boto3.Session]:
    """
    Assume a role and return a new session.
    
    Args:
        session (boto3.Session): Base AWS session
        role_arn (str): ARN of the role to assume
        role_session_name (str): Name for the role session
        region (str): AWS region
        dry_run (bool): Whether this is a dry run
        external_id (str): Optional external ID for role assumption
        
    Returns:
        Optional[boto3.Session]: New session with assumed role credentials, or None if failed
    """
    try:
        LOGGER.info(f"Assuming role: {role_arn}")
        
        if dry_run:
            print(f"[DRY RUN] Assuming role: {role_arn}")
        
        # Get STS client from base session
        sts_client = session.client('sts')
        
        # Prepare assume role parameters
        assume_role_params = {
            'RoleArn': role_arn,
            'RoleSessionName': role_session_name,
            'DurationSeconds': 3600  # 1 hour
        }
        
        # Add external ID if provided
        if external_id:
            assume_role_params['ExternalId'] = external_id
        
        # Assume the role
        response = sts_client.assume_role(**assume_role_params)
        
        # Create new session with assumed role credentials
        assumed_session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken'],
            region_name=region
        )
        
        # Verify the assumption worked
        sts_client = assumed_session.client('sts')
        identity = sts_client.get_caller_identity()
        
        LOGGER.info(f"Successfully assumed role. Account: {identity['Account']}, ARN: {identity['Arn']}")
        print(f"✓ Successfully assumed role in account: {identity['Account']}")
        
        return assumed_session
        
    except ClientError as e:
        LOGGER.error(f"Error assuming role {role_arn}: {e}")
        print(f"✗ Error assuming role {role_arn}: {e}")
        return None
    except Exception as e:
        LOGGER.error(f"Unexpected error assuming role {role_arn}: {e}")
        print(f"✗ Unexpected error assuming role {role_arn}: {e}")
        return None


def get_s3_buckets(s3_client, dry_run: bool) -> List[str]:
    """
    Get list of S3 buckets using the provided S3 client.
    
    Args:
        s3_client: S3 client (from assumed role session)
        dry_run (bool): Whether this is a dry run
        
    Returns:
        List[str]: List of bucket names
    """
    try:
        LOGGER.info("Listing S3 buckets")
        
        if dry_run:
            print(f"[DRY RUN] Listing S3 buckets")
        
        if not s3_client:
            LOGGER.error("S3 client is None")
            print("Error: S3 client is None")
            return []
        
        response = s3_client.list_buckets()
        buckets = [bucket['Name'] for bucket in response['Buckets']]
        
        LOGGER.info(f"Found {len(buckets)} S3 buckets")
        for bucket in buckets:
            LOGGER.debug(f"Found bucket: {bucket}")
        
        return buckets
    except ClientError as e:
        LOGGER.error(f"Error listing S3 buckets: {e}")
        print(f"Error listing S3 buckets: {e}")
        return []


def get_bucket_policy(s3_client, bucket_name: str, dry_run: bool) -> Dict[str, Any]:
    """
    Get the current bucket policy for an S3 bucket.
    
    Args:
        s3_client: S3 client (from assumed role session)
        bucket_name (str): Name of the S3 bucket
        dry_run (bool): Whether this is a dry run
        
    Returns:
        Dict[str, Any]: Current bucket policy or empty dict if no policy
    """
    try:
        LOGGER.info(f"Getting bucket policy for: {bucket_name}")
        
        if dry_run:
            print(f"[DRY RUN] Getting bucket policy for: {bucket_name}")
        
        if not s3_client:
            LOGGER.error("S3 client is None")
            print("Error: S3 client is None")
            return {}
        
        response = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy = json.loads(response['Policy'])
        
        LOGGER.info(f"Successfully retrieved policy for {bucket_name}")
        if dry_run:
            print(f"[DRY RUN] Retrieved policy for {bucket_name}")
        else:
            print(f"Retrieved policy for {bucket_name}")
        
        return policy
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            LOGGER.info(f"No existing policy found for {bucket_name}")
            if dry_run:
                print(f"[DRY RUN] No existing policy found for {bucket_name}")
            else:
                print(f"No existing policy found for {bucket_name}")
            return {}
        else:
            LOGGER.error(f"Error getting bucket policy for {bucket_name}: {e}")
            print(f"Error getting bucket policy for {bucket_name}: {e}")
            return {}


def download_bucket_policy(s3_client, bucket_name: str, account_id: str, dry_run: bool) -> str:
    """
    Download and save the current bucket policy to a local file.
    
    Args:
        s3_client: S3 client (from assumed role session)
        bucket_name (str): Name of the S3 bucket
        account_id (str): AWS account ID
        dry_run (bool): Whether this is a dry run
        
    Returns:
        str: Path to the saved policy file
    """
    try:
        LOGGER.info(f"Downloading policy backup for bucket: {bucket_name}")
        
        # Get current policy
        current_policy = get_bucket_policy(s3_client, bucket_name, dry_run)
        
        if not current_policy:
            # No policy exists, create an empty one for backup
            current_policy = {
                "Version": "2012-10-17",
                "Statement": []
            }
            LOGGER.info(f"Created empty policy template for {bucket_name}")
        
        # Create filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{account_id}_{bucket_name}_policy_backup_{timestamp}.json"
        filepath = os.path.join(BACKUP_DIR, filename)
        
        # Save policy to file
        with open(filepath, 'w') as f:
            json.dump(current_policy, f, indent=2)
        
        LOGGER.info(f"Policy backup saved to: {filepath}")
        if dry_run:
            print(f"[DRY RUN] Would save policy backup to: {filepath}")
        else:
            print(f"✓ Saved policy backup to: {filepath}")
        
        return filepath
        
    except Exception as e:
        LOGGER.error(f"Error saving policy backup for {bucket_name}: {e}")
        print(f"✗ Error saving policy backup for {bucket_name}: {e}")
        return ""


def update_bucket_policy_deny_http(s3_client, bucket_name: str, account_id: str, dry_run: bool) -> bool:
    """
    Update S3 bucket policy to deny HTTP requests.
    
    Args:
        s3_client: S3 client (from assumed role session)
        bucket_name (str): Name of the S3 bucket
        account_id (str): AWS account ID
        dry_run (bool): Whether this is a dry run
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        LOGGER.info(f"Processing bucket policy update for: {bucket_name}")
        
        # Download current policy as backup
        backup_file = download_bucket_policy(s3_client, bucket_name, account_id, dry_run)
        
        # Get current policy
        current_policy = get_bucket_policy(s3_client, bucket_name, dry_run)
        
        # Create HTTP deny statement
        http_deny_statement = {
            "Sid": "DenyHttpRequests",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                f"arn:aws:s3:::{bucket_name}",
                f"arn:aws:s3:::{bucket_name}/*"
            ],
            "Condition": {
                "StringEquals": {
                    "aws:SecureTransport": "false"
                }
            }
        }
        
        # Initialize policy structure if empty
        if not current_policy:
            current_policy = {
                "Version": "2012-10-17",
                "Statement": []
            }
        
        # Check if HTTP deny statement already exists
        existing_deny = False
        for statement in current_policy.get('Statement', []):
            if (statement.get('Effect') == 'Deny' and
                'Condition' in statement and
                'StringEquals' in statement['Condition'] and
                statement['Condition']['StringEquals'].get('aws:SecureTransport') == 'false'):
                existing_deny = True
                break
        
        if dry_run:
            if existing_deny:
                LOGGER.info(f"Bucket {bucket_name} already has HTTP deny policy (dry run)")
                print(f"[DRY RUN] ✓ Bucket {bucket_name} already has HTTP deny policy")
            else:
                LOGGER.info(f"Would update bucket policy for {bucket_name} to deny HTTP requests (dry run)")
                print(f"[DRY RUN] ✓ Would update bucket policy for {bucket_name} to deny HTTP requests")
                print(f"[DRY RUN]   Would add policy statement: {json.dumps(http_deny_statement, indent=2)}")
                print(f"[DRY RUN]   Current policy has {len(current_policy.get('Statement', []))} statements")
            return True
        
        if not existing_deny:
            # Add HTTP deny statement
            if 'Statement' not in current_policy:
                current_policy['Statement'] = []
            current_policy['Statement'].append(http_deny_statement)
            
            LOGGER.info(f"Adding HTTP deny statement to bucket policy: {bucket_name}")
            
            # Update bucket policy (skip in dry run)
            if not dry_run:
                if not s3_client:
                    LOGGER.error("S3 client is None")
                    print("Error: S3 client is None")
                    return False
                
                s3_client.put_bucket_policy(
                    Bucket=bucket_name,
                    Policy=json.dumps(current_policy, indent=2)
                )
                
                LOGGER.info(f"Successfully updated bucket policy for {bucket_name}")
                print(f"✓ Updated bucket policy for {bucket_name} to deny HTTP requests")
            else:
                LOGGER.info(f"[DRY RUN] Would update bucket policy for {bucket_name}")
                print(f"[DRY RUN] ✓ Would update bucket policy for {bucket_name} to deny HTTP requests")
            
            return True
        else:
            LOGGER.info(f"Bucket {bucket_name} already has HTTP deny policy")
            print(f"✓ Bucket {bucket_name} already has HTTP deny policy")
            return True
            
    except ClientError as e:
        LOGGER.error(f"Error updating bucket policy for {bucket_name}: {e}")
        print(f"✗ Error updating bucket policy for {bucket_name}: {e}")
        return False


def process_account(shared_session: boto3.Session, target_account_info: Dict[str, str], region: str, dry_run: bool) -> Dict[str, Any]:
    """
    Process a single target account to update S3 bucket policies.
    
    Args:
        shared_session (boto3.Session): Session authenticated to shared account
        target_account_info (Dict[str, str]): Target account information from CSV
        region (str): AWS region
        dry_run (bool): Whether this is a dry run
        
    Returns:
        Dict[str, Any]: Results of processing the account
    """
    account_id = target_account_info['account_id']
    role_arn = target_account_info['role_arn']
    role_session_name = target_account_info['role_session_name']
    
    LOGGER.info(f"Starting processing for target account: {account_id}")
    
    if dry_run:
        print(f"\n[DRY RUN] Processing target account: {account_id}")
        print(f"[DRY RUN] Target Role ARN: {role_arn}")
    else:
        print(f"\nProcessing target account: {account_id}")
        print(f"Target Role ARN: {role_arn}")
    
    try:
        # Assume target account role from shared account session
        assumed_session = assume_role(shared_session, role_arn, role_session_name, region, dry_run)
        
        if not assumed_session and not dry_run:
            return {
                'account_id': account_id,
                'error': 'Failed to assume role',
                'total_buckets': 0,
                'success_count': 0,
                'failed_buckets': []
            }
        
        # Create S3 client with assumed role session
        if not assumed_session:
            return {
                'account_id': account_id,
                'error': 'Failed to assume role',
                'total_buckets': 0,
                'success_count': 0,
                'failed_buckets': []
            }
        s3_client = assumed_session.client('s3')
        
        # Get S3 buckets (always perform actual listing, even in dry run)
        buckets = get_s3_buckets(s3_client, dry_run)
        if dry_run:
            print(f"[DRY RUN] Found {len(buckets)} S3 buckets in account {account_id}")
        else:
            print(f"Found {len(buckets)} S3 buckets in account {account_id}")
        
        # Update bucket policies
        success_count = 0
        failed_buckets = []
        
        for bucket in buckets:
            LOGGER.info(f"Processing bucket: {bucket} in account: {account_id}")
            if update_bucket_policy_deny_http(s3_client, bucket, account_id, dry_run):
                success_count += 1
                if dry_run:
                    LOGGER.info(f"[DRY RUN] Would successfully process bucket: {bucket}")
                else:
                    LOGGER.info(f"Successfully processed bucket: {bucket}")
            else:
                failed_buckets.append(bucket)
                if dry_run:
                    LOGGER.error(f"[DRY RUN] Would fail to process bucket: {bucket}")
                else:
                    LOGGER.error(f"Failed to process bucket: {bucket}")
        
        LOGGER.info(f"Completed processing account {account_id}. Success: {success_count}, Failed: {len(failed_buckets)}")
        
        return {
            'account_id': account_id,
            'total_buckets': len(buckets),
            'success_count': success_count,
            'failed_buckets': failed_buckets
        }
        
    except Exception as e:
        LOGGER.error(f"Error processing account {account_id}: {e}")
        if dry_run:
            print(f"[DRY RUN] ✗ Would encounter error processing account {account_id}: {e}")
        else:
            print(f"✗ Error processing account {account_id}: {e}")
        return {
            'account_id': account_id,
            'error': str(e),
            'total_buckets': 0,
            'success_count': 0,
            'failed_buckets': []
        }


def run_script(csv_file_path: str, region: str, dry_run: bool) -> None:
    """
    Main execution function to process accounts from CSV and update S3 bucket policies.
    Authenticates directly to shared account using environment variables, then assumes roles in target accounts.
    
    Args:
        csv_file_path (str): Path to the CSV file containing target account information
        region (str): AWS region
        dry_run (bool): Whether this is a dry run
    """
    LOGGER.info("Starting S3 HTTP Deny Policy Update script with CSV input")
    
    if dry_run:
        print("Starting S3 HTTP Deny Policy Update (DRY RUN)")
        print("=" * 60)
    else:
        print("Starting S3 HTTP Deny Policy Update")
        print("=" * 50)
    
    try:
        # Read target accounts from CSV
        if dry_run:
            print("[DRY RUN] Reading target accounts from CSV file...")
        else:
            print("Reading target accounts from CSV file...")
            print(f"Policy backups will be saved to: {BACKUP_DIR}")
        
        target_accounts = read_csv_accounts(csv_file_path, dry_run)
        
        if not target_accounts:
            LOGGER.warning("No target accounts found in CSV file")
            if dry_run:
                print("[DRY RUN] No target accounts found in CSV file.")
            else:
                print("No target accounts found in CSV file.")
            return
        
        LOGGER.info(f"Found {len(target_accounts)} target accounts to process")
        if dry_run:
            print(f"[DRY RUN] Found {len(target_accounts)} target accounts to process")
        else:
            print(f"Found {len(target_accounts)} target accounts to process")
        
        # Create AWS session authenticated to shared account using environment variables
        shared_session = create_aws_session(region)
        
        # Verify we're authenticated to the shared account
        try:
            sts_client = shared_session.client('sts')
            identity = sts_client.get_caller_identity()
            LOGGER.info(f"Authenticated to shared account: {identity['Account']}")
            if dry_run:
                print(f"[DRY RUN] Authenticated to shared account: {identity['Account']}")
            else:
                print(f"✓ Authenticated to shared account: {identity['Account']}")
        except Exception as e:
            LOGGER.error(f"Failed to verify shared account authentication: {e}")
            print(f"✗ Failed to verify shared account authentication: {e}")
            print("Please check your AWS credentials and ensure they have access to the shared account.")
            return
        
        # Process each target account
        results = []
        for i, target_account_info in enumerate(target_accounts, 1):
            LOGGER.info(f"Processing target account {i}/{len(target_accounts)}: {target_account_info['account_id']}")
            result = process_account(shared_session, target_account_info, region, dry_run)
            results.append(result)
        
        # Print summary
        if dry_run:
            print("\n" + "=" * 60)
            print("DRY RUN SUMMARY")
            print("=" * 60)
        else:
            print("\n" + "=" * 50)
            print("SUMMARY")
            print("=" * 50)
        
        total_accounts = len(results)
        successful_accounts = len([r for r in results if 'error' not in r])
        total_buckets = sum([r.get('total_buckets', 0) for r in results])
        total_successful_updates = sum([r.get('success_count', 0) for r in results])
        
        LOGGER.info(f"Script completed. Total accounts: {total_accounts}, Successful: {successful_accounts}, Total buckets: {total_buckets}, Updates: {total_successful_updates}")
        
        if dry_run:
            print(f"[DRY RUN] Total accounts that would be processed: {total_accounts}")
            print(f"[DRY RUN] Successful accounts: {successful_accounts}")
            print(f"[DRY RUN] Total buckets that would be found: {total_buckets}")
            print(f"[DRY RUN] Total policy updates that would be made: {total_successful_updates}")
        else:
            print(f"Total accounts processed: {total_accounts}")
            print(f"Successful accounts: {successful_accounts}")
            print(f"Total buckets found: {total_buckets}")
            print(f"Total successful policy updates: {total_successful_updates}")
        
        # Print failed accounts
        failed_accounts = [r for r in results if 'error' in r]
        if failed_accounts:
            LOGGER.warning(f"Failed accounts: {len(failed_accounts)}")
            if dry_run:
                print(f"\n[DRY RUN] Accounts that would fail ({len(failed_accounts)}):")
            else:
                print(f"\nFailed accounts ({len(failed_accounts)}):")
            for account in failed_accounts:
                print(f"  - {account['account_id']}: {account['error']}")
        
        # Print accounts with failed buckets
        accounts_with_failures = [r for r in results if r.get('failed_buckets')]
        if accounts_with_failures:
            LOGGER.warning(f"Accounts with bucket failures: {len(accounts_with_failures)}")
            if dry_run:
                print(f"\n[DRY RUN] Accounts with bucket update failures ({len(accounts_with_failures)}):")
            else:
                print(f"\nAccounts with failed bucket updates ({len(accounts_with_failures)}):")
            for account in accounts_with_failures:
                print(f"  - {account['account_id']}: {account['failed_buckets']}")
        
    except Exception as e:
        LOGGER.error(f"Error during execution: {e}")
        if dry_run:
            print(f"[DRY RUN] Error during execution: {e}")
        else:
            print(f"Error during execution: {e}")
        sys.exit(1)


def main():
    """Main function to parse arguments and run the script."""
    parser = argparse.ArgumentParser(
        description='Update S3 bucket policies to deny HTTP requests across multiple AWS accounts using CSV input. Authenticates directly to shared account using environment variables and assumes cross-account roles.'
    )
    parser.add_argument(
        'csv_file',
        help='Path to CSV file containing target account information (target_account_id,target_role_arn,target_role_session_name)'
    )
    parser.add_argument(
        '--region',
        default='us-east-1',
        help='AWS region (default: us-east-1)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Preview all activities without making actual changes'
    )
    
    args = parser.parse_args()
    
    # Set global variables
    global REGION, DRY_RUN
    REGION = args.region
    DRY_RUN = args.dry_run
    
    # Setup logging and get backup directory
    backup_dir = setup_logging(args.region, args.dry_run)
    
    # Check for AWS credentials
    aws_access_key = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    
    if not aws_access_key or not aws_secret_key:
        print("Warning: AWS_ACCESS_KEY_ID and/or AWS_SECRET_ACCESS_KEY not found in environment variables.")
        print("The script will attempt to use the default AWS credential chain.")
        print("Make sure you have configured AWS credentials using one of these methods:")
        print("  - AWS CLI: aws configure")
        print("  - Environment variables: export AWS_ACCESS_KEY_ID=your_key")
        print("  - IAM roles (if running on EC2)")
        print()
    
    # Run the script
    run_script(args.csv_file, args.region, args.dry_run)


if __name__ == "__main__":
    main()
