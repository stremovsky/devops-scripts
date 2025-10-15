#!/usr/bin/env python3
"""
ECR Repository Scanner
=====================
A comprehensive script to scan all enabled AWS regions for ECR repositories.
Shows repository details, public repositories, and provides a user-friendly interface.

Author: Generated Script
Usage: python3 list-ecrs.py
"""

import boto3
import json
import sys
import argparse
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Unicode characters for better UI
CHECKMARK = "✅"
CROSS = "❌"
WARNING = "⚠️"
INFO = "ℹ️"
FOLDER = "📁"
GLOBE = "🌐"
LOCK = "🔒"
UNLOCK = "🔓"
SPARKLES = "✨"
ROCKET = "🚀"
CLOCK = "⏰"
GEAR = "⚙️"

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header():
    """Print a beautiful header"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║                    🐳 ECR Repository Scanner 🐳              ║")
    print("║                                                              ║")
    print("║  Scanning all enabled AWS regions for ECR repositories...    ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"{Colors.ENDC}")

def print_section(title, icon=INFO):
    """Print a section header"""
    print(f"\n{Colors.OKBLUE}{Colors.BOLD}{icon} {title}{Colors.ENDC}")
    print("─" * (len(title) + 4))

def print_success(message):
    """Print success message"""
    print(f"{Colors.OKGREEN}{CHECKMARK} {message}{Colors.ENDC}")

def print_error(message):
    """Print error message"""
    print(f"{Colors.FAIL}{CROSS} {message}{Colors.ENDC}")

def print_warning(message):
    """Print warning message"""
    print(f"{Colors.WARNING}{WARNING} {message}{Colors.ENDC}")

def print_info(message):
    """Print info message"""
    print(f"{Colors.OKCYAN}{INFO} {message}{Colors.ENDC}")

def get_enabled_regions():
    """Get all enabled regions for the AWS account"""
    # Predefined list of AWS regions (as fallback when ec2:DescribeRegions is not allowed)
    aws_regions = [
        'af-south-1',     # Africa (Cape Town)
        'ap-east-1',      # Asia Pacific (Hong Kong)
        'ap-northeast-1', # Asia Pacific (Tokyo)
        'ap-northeast-2', # Asia Pacific (Seoul)
        'ap-northeast-3', # Asia Pacific (Osaka)
        'ap-south-1',     # Asia Pacific (Mumbai)
        'ap-south-2',     # Asia Pacific (Hyderabad)
        'ap-southeast-1', # Asia Pacific (Singapore)
        'ap-southeast-2', # Asia Pacific (Sydney)
        'ap-southeast-3', # Asia Pacific (Jakarta)
        'ap-southeast-4', # Asia Pacific (Melbourne)
        'ca-central-1',   # Canada (Central)
        'ca-west-1',      # Canada (Calgary)
        'eu-central-1',   # Europe (Frankfurt)
        'eu-central-2',   # Europe (Zurich)
        'eu-north-1',     # Europe (Stockholm)
        'eu-south-1',     # Europe (Milan)
        'eu-south-2',     # Europe (Spain)
        'eu-west-1',      # Europe (Ireland)
        'eu-west-2',      # Europe (London)
        'eu-west-3',      # Europe (Paris)
        'il-central-1',   # Israel (Tel Aviv)
        'me-central-1',   # Middle East (UAE)
        'me-south-1',     # Middle East (Bahrain)
        'sa-east-1',      # South America (São Paulo)
        'us-east-1',      # US East (N. Virginia)
        'us-east-2',      # US East (Ohio)
        'us-west-1',      # US West (N. California)
        'us-west-2',      # US West (Oregon)
        'us-gov-east-1',  # AWS GovCloud (US-East)
        'us-gov-west-1'   # AWS GovCloud (US-West)
    ]
    
    try:
        # Try to get regions dynamically first
        ec2_client = boto3.client('ec2')
        response = ec2_client.describe_regions()
        regions = [region['RegionName'] for region in response['Regions']]
        print_success("Successfully discovered regions dynamically")
        return sorted(regions)
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'UnauthorizedOperation':
            print_warning("ec2:DescribeRegions permission denied, using predefined region list")
            print_info(f"Scanning {len(aws_regions)} predefined AWS regions")
            return sorted(aws_regions)
        else:
            print_error(f"Failed to get enabled regions: {str(e)}")
            print_warning("Falling back to predefined region list")
            return sorted(aws_regions)
    except Exception as e:
        print_error(f"Failed to get enabled regions: {str(e)}")
        print_warning("Falling back to predefined region list")
        return sorted(aws_regions)

def check_ecr_service_availability(region):
    """Check if ECR service is available in the region"""
    try:
        ecr_client = boto3.client('ecr', region_name=region)
        # Try to list repositories to check if ECR is available
        ecr_client.describe_repositories(maxResults=1)
        return True
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code in ['InvalidSignature', 'SignatureDoesNotMatch']:
            return True  # Service exists but auth issue
        return False
    except Exception:
        return False

def get_ecr_repositories(region):
    """Get all ECR repositories in a specific region"""
    try:
        ecr_client = boto3.client('ecr', region_name=region)
        repositories = []
        
        # Get all repositories
        paginator = ecr_client.get_paginator('describe_repositories')
        for page in paginator.paginate():
            for repo in page['repositories']:
                repo_info = {
                    'name': repo['repositoryName'],
                    'uri': repo['repositoryUri'],
                    'created': repo['createdAt'],
                    'registry_id': repo['registryId'],
                    'region': region
                }
                
                # Check if repository is public
                try:
                    policy_response = ecr_client.get_repository_policy(
                        repositoryName=repo['repositoryName']
                    )
                    policy = json.loads(policy_response['policyText'])
                    repo_info['is_public'] = is_repository_public(policy)
                except ClientError:
                    repo_info['is_public'] = False
                
                # Get image count
                try:
                    images_response = ecr_client.describe_images(
                        repositoryName=repo['repositoryName'],
                        maxResults=1
                    )
                    repo_info['image_count'] = len(images_response['imageDetails'])
                except ClientError:
                    repo_info['image_count'] = 0
                
                repositories.append(repo_info)
        
        return repositories
    except Exception as e:
        print_warning(f"Error scanning region {region}: {str(e)}")
        return []

def is_repository_public(policy):
    """Check if repository policy allows public access"""
    try:
        for statement in policy.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                principal = statement.get('Principal', {})
                if principal == '*' or (isinstance(principal, dict) and '*' in principal.get('AWS', [])):
                    return True
        return False
    except Exception:
        return False

def scan_region(region):
    """Scan a single region for ECR repositories"""
    print_info(f"Scanning region: {region}")
    
    if not check_ecr_service_availability(region):
        return {
            'region': region,
            'ecr_available': False,
            'repositories': [],
            'public_repos': []
        }
    
    repositories = get_ecr_repositories(region)
    public_repos = [repo for repo in repositories if repo['is_public']]
    
    return {
        'region': region,
        'ecr_available': True,
        'repositories': repositories,
        'public_repos': public_repos
    }

def format_datetime(dt):
    """Format datetime for display"""
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

def print_repository_details(repo):
    """Print detailed repository information"""
    print(f"    {FOLDER} {Colors.BOLD}{repo['name']}{Colors.ENDC}")
    print(f"        URI: {repo['uri']}")
    print(f"        Created: {format_datetime(repo['created'])}")
    print(f"        Images: {repo['image_count']}")
    
    if repo['is_public']:
        print(f"        Access: {Colors.WARNING}{UNLOCK} PUBLIC{Colors.ENDC}")
    else:
        print(f"        Access: {Colors.OKGREEN}{LOCK} PRIVATE{Colors.ENDC}")

def print_summary(results):
    """Print summary of the scan results"""
    print_section("📊 Scan Summary", SPARKLES)
    
    total_regions = len(results)
    regions_with_ecr = len([r for r in results if r['ecr_available']])
    total_repos = sum(len(r['repositories']) for r in results)
    total_public_repos = sum(len(r['public_repos']) for r in results)
    
    print(f"{Colors.OKGREEN}Total regions scanned: {total_regions}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}Regions with ECR available: {regions_with_ecr}{Colors.ENDC}")
    print(f"{Colors.OKCYAN}Total repositories found: {total_repos}{Colors.ENDC}")
    
    if total_public_repos > 0:
        print(f"{Colors.WARNING}⚠️  PUBLIC repositories found: {total_public_repos}{Colors.ENDC}")
    else:
        print(f"{Colors.OKGREEN}✅ No public repositories found{Colors.ENDC}")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Scan AWS ECR repositories across all regions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 list-ecrs.py                    # Scan all regions
  python3 list-ecrs.py --regions us-east-1 us-west-2  # Scan specific regions
  python3 list-ecrs.py --regions us-east-1 --max-workers 5  # Limit concurrent workers
        """
    )
    
    parser.add_argument(
        '--regions',
        nargs='+',
        help='Specific regions to scan (default: all AWS regions)'
    )
    
    parser.add_argument(
        '--max-workers',
        type=int,
        default=10,
        help='Maximum number of concurrent workers (default: 10)'
    )
    
    return parser.parse_args()

def main():
    """Main function"""
    args = parse_arguments()
    print_header()
    
    try:
        # Test AWS credentials
        sts_client = boto3.client('sts')
        identity = sts_client.get_caller_identity()
        print_success(f"Authenticated as: {identity.get('Arn', 'Unknown')}")
        print_info(f"Account ID: {identity.get('Account', 'Unknown')}")
        
    except NoCredentialsError:
        print_error("AWS credentials not found. Please configure your credentials.")
        sys.exit(1)
    except Exception as e:
        print_error(f"Failed to authenticate with AWS: {str(e)}")
        sys.exit(1)
    
    # Get regions to scan
    print_section("🌍 Discovering AWS Regions", GEAR)
    
    if args.regions:
        regions = args.regions
        print_info(f"Using specified regions: {', '.join(regions)}")
    else:
        regions = get_enabled_regions()
    
    if not regions:
        print_error("No regions found or failed to get regions")
        sys.exit(1)
    
    print_success(f"Will scan {len(regions)} region(s)")
    print_info("Regions: " + ", ".join(regions))
    
    # Scan regions concurrently
    print_section("🔍 Scanning ECR Repositories", ROCKET)
    results = []
    
    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        future_to_region = {executor.submit(scan_region, region): region for region in regions}
        
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print_error(f"Failed to scan region {region}: {str(e)}")
                results.append({
                    'region': region,
                    'ecr_available': False,
                    'repositories': [],
                    'public_repos': []
                })
    
    # Sort results by region name
    results.sort(key=lambda x: x['region'])
    
    # Print detailed results
    print_section("📋 Detailed Results", FOLDER)
    
    for result in results:
        region = result['region']
        print(f"\n{Colors.BOLD}📍 Region: {region}{Colors.ENDC}")
        
        if not result['ecr_available']:
            print(f"    {CROSS} ECR service not available in this region")
            continue
        
        if not result['repositories']:
            print(f"    {INFO} No ECR repositories found")
            continue
        
        print(f"    {CHECKMARK} Found {len(result['repositories'])} repository(ies)")
        
        for repo in result['repositories']:
            print_repository_details(repo)
    
    # Print public repositories summary
    all_public_repos = []
    for result in results:
        all_public_repos.extend(result['public_repos'])
    
    if all_public_repos:
        print_section("⚠️  Public Repositories Found", WARNING)
        for repo in all_public_repos:
            print(f"{Colors.WARNING}🌐 {repo['region']}: {repo['name']} - {repo['uri']}{Colors.ENDC}")
    
    # Print summary
    print_summary(results)
    
    print(f"\n{Colors.OKGREEN}{SPARKLES} Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}\n")

if __name__ == "__main__":
    main()
