#!/usr/bin/env python3
"""
AWS KMS Keys Listing Script

This script lists KMS keys in us-east-2 region using the 'jenkins' AWS profile.
It shows keys that are not expiring and their aliases and tags.
If StackPrefix tag contains 'test' or 'ipv6', the key should expire in 7 days.
"""

"""
📊 FINAL SUMMARY:
Total keys processed: 189
🚨 Keys to expire (not in EKS exclude vector): 167
✅ Keys not expiring (in EKS exclude vector): 22
🔒 Exclude vector from EKS clusters: ['cd14011a', 'no131119', 'cd130906', 'radcom', 'vz131507']
✅ Processing complete.
"""

import boto3
import json
import sys
import argparse
from datetime import datetime, timedelta
from botocore.exceptions import ClientError, ProfileNotFound

# Global AWS profile configuration
AWS_PROFILE = 'jenkinsold'

def get_available_regions():
    """Get list of available AWS regions."""
    try:
        session = boto3.Session(profile_name=AWS_PROFILE)
        ec2_client = session.client('ec2', region_name='us-east-1')  # Use us-east-1 to get regions
        response = ec2_client.describe_regions()
        regions = [region['RegionName'] for region in response['Regions']]
        return regions
    except ProfileNotFound:
        print(f"Error: '{AWS_PROFILE}' AWS profile not found. Please configure it first.")
        return []
    except Exception as e:
        print(f"Error getting available regions: {e}")
        return []

def get_account_info():
    """Get AWS account information."""
    try:
        session = boto3.Session(profile_name=AWS_PROFILE)
        sts_client = session.client('sts', region_name='us-east-1')
        response = sts_client.get_caller_identity()
        return {
            'account_id': response.get('Account', 'Unknown'),
            'user_id': response.get('UserId', 'Unknown'),
            'arn': response.get('Arn', 'Unknown')
        }
    except ProfileNotFound:
        print(f"Error: '{AWS_PROFILE}' AWS profile not found. Please configure it first.")
        return None
    except Exception as e:
        print(f"Error getting account info: {e}")
        return None

def get_kms_client(region='us-east-2'):
    """Initialize KMS client with jenkins profile and specified region."""
    try:
        session = boto3.Session(profile_name=AWS_PROFILE)
        kms_client = session.client('kms', region_name=region)
        return kms_client
    except ProfileNotFound:
        print(f"Error: '{AWS_PROFILE}' AWS profile not found. Please configure it first.")
        return None
    except Exception as e:
        print(f"Error initializing KMS client for region {region}: {e}")
        return None

def get_eks_client(region='us-east-2'):
    """Initialize EKS client with jenkins profile and specified region."""
    try:
        session = boto3.Session(profile_name=AWS_PROFILE)
        eks_client = session.client('eks', region_name=region)
        return eks_client
    except ProfileNotFound:
        print(f"Error: '{AWS_PROFILE}' AWS profile not found. Please configure it first.")
        return None
    except Exception as e:
        print(f"Error initializing EKS client for region {region}: {e}")
        return None

def get_key_aliases(kms_client, key_id):
    """Get all aliases for a KMS key."""
    try:
        response = kms_client.list_aliases(KeyId=key_id)
        aliases = [alias['AliasName'] for alias in response.get('Aliases', [])]
        return aliases
    except ClientError as e:
        print(f"Error getting aliases for key {key_id}: {e}")
        return []

def get_key_tags(kms_client, key_id):
    """Get all tags for a KMS key."""
    try:
        response = kms_client.list_resource_tags(KeyId=key_id)
        tags = {tag['TagKey']: tag['TagValue'] for tag in response.get('Tags', [])}
        return tags
    except ClientError as e:
        print(f"Error getting tags for key {key_id}: {e}")
        return {}

def get_eks_clusters_with_stackprefix(eks_client):
    """Get EKS clusters and extract StackPrefix tags to create exclude vector."""
    exclude_vector = set()
    
    try:
        print("🔍 Fetching EKS clusters to build exclude vector...")
        response = eks_client.list_clusters()
        cluster_names = response.get('clusters', [])
        
        if not cluster_names:
            print("No EKS clusters found.")
            return exclude_vector
        
        print(f"Found {len(cluster_names)} EKS clusters.")
        
        for cluster_name in cluster_names:
            try:
                # Get cluster details including tags
                cluster_response = eks_client.describe_cluster(name=cluster_name)
                cluster = cluster_response.get('cluster', {})
                tags = cluster.get('tags', {})
                
                # Check for StackPrefix tag
                stack_prefix = tags.get('StackPrefix', '')
                if stack_prefix:
                    exclude_vector.add(stack_prefix)
                    print(f"  📋 EKS Cluster: {cluster_name} -> StackPrefix: {stack_prefix}")
                
            except ClientError as e:
                print(f"  ⚠️  Error getting details for cluster {cluster_name}: {e}")
                continue
        
        print(f"✅ Built exclude vector with {len(exclude_vector)} StackPrefix values: {list(exclude_vector)}")
        
    except ClientError as e:
        print(f"Error listing EKS clusters: {e}")
    except Exception as e:
        print(f"Unexpected error fetching EKS clusters: {e}")
    
    return exclude_vector

def should_expire_key(tags, exclude_vector, key, aliases):
    """Check if key should expire based on StackPrefix tag not being in exclude vector."""
    # First check if it's an AWS-managed key - never expire these
    if is_aws_managed_key(key, aliases):
        return False
    
    stack_prefix = tags.get('StackPrefix', '')
    
    # If no exclude vector, expire all user keys (no active clusters to protect)
    if len(exclude_vector) == 0:
        return True
    # If key has no StackPrefix tag, don't expire it automatically
    if not stack_prefix:
        return False
    # Only expire if StackPrefix exists but is not in exclude vector
    return stack_prefix not in exclude_vector

def is_aws_managed_key(key, aliases):
    """Check if a key is AWS-managed and should not be deleted."""
    # Check for AWS service aliases
    aws_service_aliases = [
        'alias/aws/ssm',
        'alias/aws/s3',
        'alias/aws/rds',
        'alias/aws/ebs',
        'alias/aws/redshift',
        'alias/aws/workspaces',
        'alias/aws/backup',
        'alias/aws/cloudtrail',
        'alias/aws/cloudwatch',
        'alias/aws/autoscaling',
        'alias/aws/ec2',
        'alias/aws/eks',
        'alias/aws/elasticfilesystem',
        'alias/aws/fsx',
        'alias/aws/kms',
        'alias/aws/lambda',
        'alias/aws/neptune',
        'alias/aws/opensearch',
        'alias/aws/sagemaker',
        'alias/aws/secretsmanager',
        'alias/aws/sns',
        'alias/aws/sqs',
        'alias/aws/transfer',
        'alias/aws/trustedadvisor',
        'alias/aws/wellarchitected'
    ]
    
    # Check if any alias matches AWS service patterns
    for alias in aliases:
        if alias in aws_service_aliases:
            return True
        # Also check for any alias starting with 'alias/aws/'
        if alias.startswith('alias/aws/'):
            return True
    
    # Check if key description indicates AWS service
    description = key.get('Description', '').lower()
    aws_service_keywords = ['aws', 'amazon', 'service', 'managed']
    if any(keyword in description for keyword in aws_service_keywords):
        return True
    
    return False

def get_key_deletion_reason(tags, exclude_vector, key, aliases):
    """Get the reason why a key is not being deleted."""
    # First check if it's an AWS-managed key
    if is_aws_managed_key(key, aliases):
        return "🔒 AWS-managed key - protected from deletion"
    
    stack_prefix = tags.get('StackPrefix', '')
    
    # If no exclude vector, all user keys should be deleted (no active clusters to protect)
    if len(exclude_vector) == 0:
        return "⚠️  No EKS clusters found - all user keys will be deleted"
    
    # If key has no StackPrefix tag, don't expire it automatically
    if not stack_prefix:
        return "🔒 No StackPrefix tag - key protected from automatic deletion"
    
    # Check if StackPrefix is in exclude vector
    if stack_prefix in exclude_vector:
        return f"🔒 StackPrefix '{stack_prefix}' found in active EKS cluster - key protected"
    
    # If we get here, the key should expire
    return f"⚠️  StackPrefix '{stack_prefix}' not found in active EKS clusters - key will be deleted"

def get_key_details(kms_client, key_id):
    """Get comprehensive key details in a single API call."""
    try:
        response = kms_client.describe_key(KeyId=key_id)
        key_metadata = response['KeyMetadata']
        
        return {
            'success': True,
            'key_state': key_metadata.get('KeyState', 'Unknown'),
            'deletion_date': key_metadata.get('DeletionDate'),
            'pending_window_in_days': key_metadata.get('PendingWindowInDays'),
            'key_metadata': key_metadata
        }
    except ClientError as e:
        return {
            'success': False,
            'key_state': 'Unknown',
            'deletion_date': None,
            'pending_window_in_days': None,
            'error': str(e),
            'key_metadata': None
        }
    except Exception as e:
        return {
            'success': False,
            'key_state': 'Unknown',
            'deletion_date': None,
            'pending_window_in_days': None,
            'error': str(e),
            'key_metadata': None
        }

def get_key_status_from_details(key_details):
    """Get key status from cached key details."""
    return key_details.get('key_state', 'Unknown')

def get_key_deletion_info_from_details(key_details):
    """Get deletion info from cached key details."""
    return {
        'key_state': key_details.get('key_state', 'Unknown'),
        'deletion_date': key_details.get('deletion_date'),
        'pending_window_in_days': key_details.get('pending_window_in_days')
    }

def is_key_expired(deletion_info):
    """Check if a key's deletion date has passed."""
    if not deletion_info or deletion_info.get('key_state') != 'PendingDeletion':
        return False
    
    deletion_date = deletion_info.get('deletion_date')
    if not deletion_date:
        return False
    
    # Check if deletion date is in the past
    now = datetime.now(deletion_date.tzinfo) if deletion_date.tzinfo else datetime.now()
    return deletion_date < now

def schedule_key_for_deletion(kms_client, key_id, key_details, days=7, dry_run=False):
    """Schedule a KMS key for deletion."""
    if dry_run:
        return {
            'success': True,
            'key_id': key_id,
            'status': 'dry_run',
            'message': f"🔍 DRY RUN: Would schedule key {key_id} for deletion in {days} days"
        }
    try:
        # Check if key is already pending deletion using cached data
        key_status = get_key_status_from_details(key_details)
        
        if key_status == 'PendingDeletion':
            return {
                'success': True,
                'key_id': key_id,
                'status': 'already_pending',
                'message': f"ℹ️  Key {key_id} is already pending deletion"
            }
        elif key_status == 'PendingImport':
            return {
                'success': False,
                'key_id': key_id,
                'error_code': 'InvalidState',
                'error_message': 'Key is pending import',
                'message': f"⚠️  Key {key_id} is in pending import state and cannot be deleted"
            }
        elif key_status == 'Disabled':
            return {
                'success': False,
                'key_id': key_id,
                'error_code': 'InvalidState',
                'error_message': 'Key is disabled',
                'message': f"⚠️  Key {key_id} is disabled and cannot be deleted"
            }
        # Schedule key for deletion
        response = kms_client.schedule_key_deletion(
            KeyId=key_id,
            PendingWindowInDays=days
        )
        
        deletion_date = response.get('DeletionDate')
        key_id_response = response.get('KeyId')
        
        return {
            'success': True,
            'key_id': key_id_response,
            'deletion_date': deletion_date,
            'message': f"✅ Successfully scheduled key {key_id} for deletion on {deletion_date}"
        }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        return {
            'success': False,
            'key_id': key_id,
            'error_code': error_code,
            'error_message': error_message,
            'message': f"❌ Failed to schedule key {key_id} for deletion: {error_code} - {error_message}"
        }
    except Exception as e:
        return {
            'success': False,
            'key_id': key_id,
            'error_message': str(e),
            'message': f"❌ Unexpected error scheduling key {key_id} for deletion: {e}"
        }

def expire_keys(kms_client, keys_to_expire, days=7):
    """Expire the list of keys that should be deleted."""
    if not keys_to_expire:
        print("📝 No keys to expire.")
        return
    
    print(f"\n🗑️  EXPIRING {len(keys_to_expire)} KEYS:")
    print("=" * 60)
    
    successful_expirations = []
    failed_expirations = []
    
    for i, key_info in enumerate(keys_to_expire, 1):
        key_id = key_info['KeyId']
        print(f"\n[{i}/{len(keys_to_expire)}] Processing: {key_id}")
        
        # Schedule for deletion
        result = schedule_key_for_deletion(kms_client, key_id, days)
        print(f"  {result['message']}")
        
        if result['success']:
            successful_expirations.append(result)
        else:
            failed_expirations.append(result)
    
    # Summary
    print(f"\n📊 EXPIRATION SUMMARY:")
    print(f"✅ Successfully scheduled: {len(successful_expirations)}")
    print(f"❌ Failed to schedule: {len(failed_expirations)}")
    
    if failed_expirations:
        print(f"\n❌ FAILED EXPIRATIONS:")
        for failure in failed_expirations:
            print(f"  • {failure['key_id']}: {failure.get('error_message', 'Unknown error')}")
    
    if successful_expirations:
        print(f"\n✅ SUCCESSFUL EXPIRATIONS:")
        for success in successful_expirations:
            print(f"  • {success['key_id']}: Deletion scheduled for {success['deletion_date']}")

def format_key_info(key, aliases, tags, should_expire, deletion_info=None, deletion_reason=None):
    """Format key information for display."""
    key_id = key['KeyId']
    key_arn = key.get('Arn', 'No ARN available')
    description = key.get('Description', 'No description')
    key_state = key.get('KeyState', 'Unknown state')
    creation_date = key.get('CreationDate', datetime.now())
    
    # Format creation date
    creation_str = creation_date.strftime('%Y-%m-%d %H:%M:%S UTC')
    
    # Format aliases
    aliases_str = ', '.join(aliases) if aliases else 'No aliases'
    
    # Format tags
    tags_str = ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'No tags'
    
    # Expiration status based on current state and deletion info
    if deletion_info and deletion_info.get('key_state') == 'PendingDeletion':
        deletion_date = deletion_info.get('deletion_date')
        if deletion_date:
            deletion_str = deletion_date.strftime('%Y-%m-%d %H:%M:%S UTC')
            if is_key_expired(deletion_info):
                expire_status = f"🗑️  EXPIRED (was scheduled for deletion on {deletion_str})"
            else:
                expire_status = f"🗑️  PENDING DELETION (will be deleted on {deletion_str})"
        else:
            expire_status = "🗑️  PENDING DELETION"
    elif should_expire:
        expire_status = "⚠️  SHOULD EXPIRE IN 7 DAYS"
    else:
        expire_status = "✅ Not scheduled for expiration"
    
    return {
        'KeyId': key_id,
        'Arn': key_arn,
        'Description': description,
        'State': key_state,
        'CreationDate': creation_str,
        'Aliases': aliases_str,
        'Tags': tags_str,
        'ExpirationStatus': expire_status,
        'DeletionInfo': deletion_info,
        'DeletionReason': deletion_reason
    }

def process_region(region, account_info, dry_run=False):
    """Process KMS keys for a specific region."""
    print(f"\n🌍 PROCESSING REGION: {region}")
    print("=" * 60)
    
    # Initialize clients for this region
    kms_client = get_kms_client(region)
    eks_client = get_eks_client(region)
    
    if not kms_client:
        print(f"❌ Failed to initialize KMS client for region {region}")
        return {
            'region': region,
            'success': False,
            'error': 'Failed to initialize KMS client',
            'keys_processed': 0,
            'keys_to_expire': 0,
            'keys_not_expiring': 0,
            'exclude_vector': []
        }
    
    if not eks_client:
        print(f"⚠️  Failed to initialize EKS client for region {region}, continuing without EKS exclude vector")
        exclude_vector = set()
    else:
        # Get EKS clusters to build exclude vector
        exclude_vector = get_eks_clusters_with_stackprefix(eks_client)
    
    try:
        # List all KMS keys
        print(f"Fetching KMS keys from {region}...")
        paginator = kms_client.get_paginator('list_keys')
        
        all_keys = []
        for page in paginator.paginate():
            all_keys.extend(page['Keys'])
        
        if not all_keys:
            print(f"No KMS keys found in {region} region.")
            return {
                'region': region,
                'success': True,
                'keys_processed': 0,
                'keys_to_expire': 0,
                'keys_not_expiring': 0,
                'exclude_vector': list(exclude_vector)
            }
        
        print(f"Found {len(all_keys)} KMS keys in {region}.\n")
        
        # Process each key and print summary immediately
        keys_to_expire = []
        keys_not_expiring = []
        
        for i, key in enumerate(all_keys, 1):
            try:
                key_id = key.get('KeyId', 'Unknown')
                
                # Skip AWS managed keys (they start with 'arn:aws:kms:')
                if key_id.startswith('arn:aws:kms:'):
                    continue
                
                print(f"🔍 Processing key {i}/{len(all_keys)}: {key_id}")
                
                # Get comprehensive key details in a single API call
                key_details = get_key_details(kms_client, key_id)
                
                if not key_details['success']:
                    print(f"  ❌ Failed to get key details: {key_details.get('error', 'Unknown error')}")
                    print("-" * 50)
                    continue
                
                # Get aliases and tags
                aliases = get_key_aliases(kms_client, key_id)
                tags = get_key_tags(kms_client, key_id)
                
                # Get deletion info from cached data
                deletion_info = get_key_deletion_info_from_details(key_details)
                is_expired = is_key_expired(deletion_info)
                
                # Check if should expire using exclude vector
                should_expire = should_expire_key(tags, exclude_vector, key, aliases)
                
                # Get deletion reason
                deletion_reason = get_key_deletion_reason(tags, exclude_vector, key, aliases)
                
                # Format key info with deletion info and reason
                key_info = format_key_info(key, aliases, tags, should_expire, deletion_info, deletion_reason)
                
                # Print summary immediately
                print(f"  📋 Key ID: {key_info['KeyId']}")
                print(f"  📝 Description: {key_info['Description']}")
                print(f"  🏷️  StackPrefix: {tags.get('StackPrefix', 'No StackPrefix tag')}")
                print(f"  🏷️  All Tags: {key_info['Tags']}")
                print(f"  🔗 Aliases: {key_info['Aliases']}")
                print(f"  📅 Created: {key_info['CreationDate']}")
                print(f"  ⚡ Status: {key_info['ExpirationStatus']}")
                print(f"  💡 Reason: {key_info['DeletionReason']}")
                
                # Handle expired keys first
                if is_expired:
                    print(f"  🗑️  Key is EXPIRED - AWS will delete it automatically")
                    # Don't add to any list since it's expired and will be auto-deleted
                elif should_expire:
                    keys_to_expire.append(key_info)
                    # Expire key immediately
                    if dry_run:
                        print(f"  🔍 DRY RUN: Would schedule key for deletion...")
                    else:
                        print(f"  🗑️  Scheduling key for deletion...")
                    result = schedule_key_for_deletion(kms_client, key_id, key_details, days=7, dry_run=dry_run)
                    print(f"  {result['message']}")
                else:
                    keys_not_expiring.append(key_info)
                
                print("-" * 50)
                    
            except Exception as e:
                print(f"❌ Error processing key {key.get('KeyId', 'Unknown')}: {e}")
                print("-" * 50)
                continue
        
        # Region summary
        print(f"\n📊 REGION {region} SUMMARY:")
        print(f"Total keys processed: {len(keys_to_expire) + len(keys_not_expiring)}")
        print(f"🚨 Keys to expire (not in EKS exclude vector): {len(keys_to_expire)}")
        print(f"✅ Keys not expiring (in EKS exclude vector): {len(keys_not_expiring)}")
        print(f"🔒 Exclude vector from EKS clusters: {list(exclude_vector)}")
        
        return {
            'region': region,
            'success': True,
            'keys_processed': len(keys_to_expire) + len(keys_not_expiring),
            'keys_to_expire': len(keys_to_expire),
            'keys_not_expiring': len(keys_not_expiring),
            'exclude_vector': list(exclude_vector)
        }
    except ClientError as e:
        print(f"AWS Error in region {region}: {e}")
        return {
            'region': region,
            'success': False,
            'error': f"AWS Error: {e}",
            'keys_processed': 0,
            'keys_to_expire': 0,
            'keys_not_expiring': 0,
            'exclude_vector': []
        }
    except Exception as e:
        print(f"Unexpected error in region {region}: {e}")
        return {
            'region': region,
            'success': False,
            'error': f"Unexpected error: {e}",
            'keys_processed': 0,
            'keys_to_expire': 0,
            'keys_not_expiring': 0,
            'exclude_vector': []
        }

def list_kms_keys(specific_regions=None, dry_run=False):
    """Main function to list KMS keys across all regions."""
    print("🔐 AWS KMS Keys Listing Script - Multi-Region")
    print("=" * 60)
    print(f"Profile: {AWS_PROFILE}")
    if specific_regions:
        print(f"Processing: Specific regions {specific_regions}")
    else:
        print("Processing: All available regions")
    print("=" * 60)
    
    # Get account information
    account_info = get_account_info()
    if account_info:
        print(f"Account ID: {account_info['account_id']}")
        print(f"User ID: {account_info['user_id']}")
        print(f"ARN: {account_info['arn']}")
        print("=" * 60)
    
    # Get regions to process
    if specific_regions:
        regions = specific_regions
        print(f"🌍 Using specified regions: {', '.join(regions)}")
    else:
        print("🌍 Discovering available AWS regions...")
        regions = get_available_regions()
        
        if not regions:
            print("❌ Failed to get available regions. Exiting.")
            return
        
        print(f"Found {len(regions)} regions: {', '.join(regions)}")
    
    print("=" * 60)
    
    # Process each region
    all_results = []
    total_keys_processed = 0
    total_keys_to_expire = 0
    total_keys_not_expiring = 0
    successful_regions = 0
    failed_regions = 0
    
    for region in regions:
        try:
            result = process_region(region, account_info, dry_run)
            all_results.append(result)
            
            if result['success']:
                successful_regions += 1
                total_keys_processed += result['keys_processed']
                total_keys_to_expire += result['keys_to_expire']
                total_keys_not_expiring += result['keys_not_expiring']
            else:
                failed_regions += 1
                
        except Exception as e:
            print(f"❌ Unexpected error processing region {region}: {e}")
            failed_regions += 1
            all_results.append({
                'region': region,
                'success': False,
                'error': f"Unexpected error: {e}",
                'keys_processed': 0,
                'keys_to_expire': 0,
                'keys_not_expiring': 0,
                'exclude_vector': []
            })
    
    # Final global summary
    print(f"\n🌍 GLOBAL SUMMARY ACROSS ALL REGIONS:")
    print("=" * 60)
    print(f"Total regions processed: {len(regions)}")
    print(f"✅ Successful regions: {successful_regions}")
    print(f"❌ Failed regions: {failed_regions}")
    print(f"📊 Total keys processed: {total_keys_processed}")
    print(f"🚨 Total keys to expire: {total_keys_to_expire}")
    print(f"✅ Total keys not expiring: {total_keys_not_expiring}")
    
    # Show results per region
    print(f"\n📋 DETAILED RESULTS BY REGION:")
    print("=" * 60)
    for result in all_results:
        if result['success']:
            print(f"✅ {result['region']}: {result['keys_processed']} keys processed "
                  f"({result['keys_to_expire']} to expire, {result['keys_not_expiring']} not expiring)")
        else:
            print(f"❌ {result['region']}: Failed - {result.get('error', 'Unknown error')}")
    
    print(f"\n✅ Multi-region processing complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='List and manage KMS keys across AWS regions',
        epilog='''
Examples:
  python list-kms-keys.py                    # Process all regions
  python list-kms-keys.py --dry-run         # Show what would be done without expiring keys
  python list-kms-keys.py --regions us-east-1 us-west-2  # Process specific regions
  python list-kms-keys.py --regions us-east-1 --dry-run  # Dry run for specific region
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--regions', nargs='+', help='Specific regions to process (e.g., --regions us-east-1 us-west-2)')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without actually expiring keys')
    
    args = parser.parse_args()
    
    if args.dry_run:
        print("🔍 DRY RUN MODE: Keys will be identified but not expired")
        print("=" * 60)
    
    
    list_kms_keys(specific_regions=args.regions, dry_run=args.dry_run)
