#!/usr/bin/env python3
"""
EC2 Public IP Scanner
====================
A comprehensive script to scan all AWS regions for EC2 instances with public IP addresses.
Identifies instances that are directly accessible from the internet.

Author: Generated Script
Usage: python3 check-ec2-public-ips.py [--regions REGION1 REGION2] [--max-workers N]
"""

import boto3
import json
import sys
import argparse
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

# Unicode characters for better UI
CHECKMARK = "✅"
CROSS = "❌"
WARNING = "⚠️"
INFO = "ℹ️"
COMPUTER = "💻"
GLOBE = "🌐"
LOCK = "🔒"
UNLOCK = "🔓"
SPARKLES = "✨"
ROCKET = "🚀"
CLOCK = "⏰"
GEAR = "⚙️"
TABLE = "📊"
LINK = "🔗"
ALERT = "🚨"
SHIELD = "🛡️"

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
    print("║                💻 EC2 Public IP Scanner 💻                   ║")
    print("║                                                              ║")
    print("║  Scanning for EC2 instances with public IP addresses...      ║")
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

def is_public_ip(ip_address):
    """Check if an IP address is public (not private)"""
    try:
        ip = ipaddress.ip_address(ip_address)
        return not ip.is_private
    except ValueError:
        return False

def get_instance_state_name(state_code):
    """Convert state code to readable state name"""
    state_names = {
        0: 'pending',
        16: 'running',
        32: 'shutting-down',
        48: 'terminated',
        64: 'stopping',
        80: 'stopped'
    }
    return state_names.get(state_code, f'unknown-{state_code}')

def get_ec2_instances(region):
    """Get all EC2 instances with public IPs in a specific region"""
    try:
        ec2_client = boto3.client('ec2', region_name=region)
        instances = []
        
        # Get all instances
        paginator = ec2_client.get_paginator('describe_instances')
        
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    # Only process running instances
                    state = get_instance_state_name(instance['State']['Code'])
                    if state != 'running':
                        continue
                    
                    # Check for public IP addresses
                    public_ips = []
                    private_ips = []
                    
                    # Primary public IP
                    if instance.get('PublicIpAddress'):
                        public_ips.append(instance['PublicIpAddress'])
                    
                    # Primary private IP
                    if instance.get('PrivateIpAddress'):
                        private_ips.append(instance['PrivateIpAddress'])
                    
                    # Network interfaces
                    for network_interface in instance.get('NetworkInterfaces', []):
                        # Public IPs from network interfaces
                        if network_interface.get('Association', {}).get('PublicIp'):
                            public_ip = network_interface['Association']['PublicIp']
                            if public_ip not in public_ips:
                                public_ips.append(public_ip)
                        
                        # Private IPs from network interfaces
                        for private_ip_info in network_interface.get('PrivateIpAddresses', []):
                            private_ip = private_ip_info.get('PrivateIpAddress')
                            if private_ip and private_ip not in private_ips:
                                private_ips.append(private_ip)
                            
                            # Check for public IP in private IP info
                            if private_ip_info.get('Association', {}).get('PublicIp'):
                                public_ip = private_ip_info['Association']['PublicIp']
                                if public_ip not in public_ips:
                                    public_ips.append(public_ip)
                    
                    # Only include instances with public IPs
                    if public_ips:
                        # Get instance name from tags
                        instance_name = 'N/A'
                        for tag in instance.get('Tags', []):
                            if tag['Key'] == 'Name':
                                instance_name = tag['Value']
                                break
                        
                        # Get security groups
                        security_groups = []
                        for sg in instance.get('SecurityGroups', []):
                            security_groups.append({
                                'id': sg['GroupId'],
                                'name': sg['GroupName']
                            })
                        
                        # Get instance type and launch time
                        instance_info = {
                            'id': instance['InstanceId'],
                            'name': instance_name,
                            'type': instance.get('InstanceType', 'N/A'),
                            'state': state,
                            'public_ips': public_ips,
                            'private_ips': private_ips,
                            'security_groups': security_groups,
                            'vpc_id': instance.get('VpcId', 'N/A'),
                            'subnet_id': instance.get('SubnetId', 'N/A'),
                            'launch_time': instance.get('LaunchTime'),
                            'region': region,
                            'console_url': f"https://{region}.console.aws.amazon.com/ec2/home?region={region}#Instances:instanceId={instance['InstanceId']}"
                        }
                        instances.append(instance_info)
        
        return instances
    except Exception as e:
        print_warning(f"Error scanning region {region}: {str(e)}")
        return []

def scan_region(region):
    """Scan a single region for EC2 instances with public IPs"""
    print_info(f"Scanning region: {region}")
    
    instances = get_ec2_instances(region)
    
    return {
        'region': region,
        'instances': instances
    }

def print_table(data, headers):
    """Print a simple table without external dependencies"""
    if not data:
        return
    
    # Calculate column widths
    col_widths = []
    for i, header in enumerate(headers):
        max_width = len(header)
        for row in data:
            if i < len(row):
                max_width = max(max_width, len(str(row[i])))
        col_widths.append(min(max_width, 50))  # Cap at 50 characters
    
    # Print header
    header_row = "│"
    separator_row = "├"
    for i, (header, width) in enumerate(zip(headers, col_widths)):
        header_row += f" {header:<{width}} │"
        separator_row += "─" * (width + 2) + "┼"
    separator_row = separator_row[:-1] + "┤"
    
    print("┌" + "─" * (len(header_row) - 2) + "┐")
    print(header_row)
    print(separator_row)
    
    # Print data rows
    for row in data:
        data_row = "│"
        for i, (cell, width) in enumerate(zip(row, col_widths)):
            cell_str = str(cell)
            if len(cell_str) > width:
                cell_str = cell_str[:width-3] + "..."
            data_row += f" {cell_str:<{width}} │"
        print(data_row)
    
    print("└" + "─" * (len(header_row) - 2) + "┘")

def print_results_table(results):
    """Print results in a formatted table by region"""
    print_section("📋 EC2 Instances with Public IPs by Region", TABLE)
    
    for result in results:
        region = result['region']
        instances = result['instances']
        
        if not instances:
            continue
        
        print(f"\n{Colors.BOLD}📍 Region: {region}{Colors.ENDC}")
        print("─" * 50)
        
        # Prepare table data
        table_data = []
        for instance in instances:
            # Format public IPs
            public_ips_str = ', '.join(instance['public_ips'])
            
            # Format security groups
            sg_names = [sg['name'] for sg in instance['security_groups']]
            sg_str = ', '.join(sg_names[:2])  # Show first 2 SGs
            if len(sg_names) > 2:
                sg_str += f" (+{len(sg_names)-2} more)"
            
            # Format launch time
            launch_time = instance['launch_time'].strftime("%Y-%m-%d %H:%M") if instance['launch_time'] else 'N/A'
            
            # Add risk indicator
            risk_indicator = " 🚨" if len(instance['public_ips']) > 1 else " ⚠️"
            
            table_data.append([
                instance['id'],
                instance['name'],
                instance['type'],
                public_ips_str + risk_indicator,
                sg_str,
                launch_time,
                f"{LINK} Console"
            ])
        
        # Print table
        headers = ["Instance ID", "Name", "Type", "Public IPs", "Security Groups", "Launch Time", "Console Link"]
        print_table(table_data, headers)
        
        # Print console URLs
        print(f"\n{Colors.OKBLUE}{LINK} Console Links:{Colors.ENDC}")
        for instance in instances:
            print(f"  • {instance['name']} ({instance['id']}): {instance['console_url']}")

def print_summary(results):
    """Print summary of the scan results"""
    print_section("📊 Scan Summary", SPARKLES)
    
    total_regions = len(results)
    total_instances = sum(len(r['instances']) for r in results)
    regions_with_public_instances = len([r for r in results if r['instances']])
    total_public_ips = sum(len(instance['public_ips']) for result in results for instance in result['instances'])
    
    print(f"{Colors.OKGREEN}Total regions scanned: {total_regions}{Colors.ENDC}")
    print(f"{Colors.WARNING}Regions with public instances: {regions_with_public_instances}{Colors.ENDC}")
    print(f"{Colors.FAIL}Total instances with public IPs: {total_instances}{Colors.ENDC}")
    print(f"{Colors.FAIL}Total public IP addresses: {total_public_ips}{Colors.ENDC}")
    
    if total_instances > 0:
        print(f"{Colors.WARNING}{ALERT} Security risk detected! Instances with public IPs found.{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{INFO} Consider using private subnets and NAT gateways for better security.{Colors.ENDC}")
    else:
        print(f"{Colors.OKGREEN}{CHECKMARK} No instances with public IPs found{Colors.ENDC}")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Scan AWS EC2 instances for public IP addresses",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 check-ec2-public-ips.py                    # Scan all regions
  python3 check-ec2-public-ips.py --regions us-east-1 us-west-2  # Scan specific regions
  python3 check-ec2-public-ips.py --regions us-east-1 --max-workers 5  # Limit concurrent workers
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
    print_section("🔍 Scanning EC2 Instances", ROCKET)
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
                    'instances': []
                })
    
    # Sort results by region name
    results.sort(key=lambda x: x['region'])
    
    # Print results
    print_results_table(results)
    
    # Print summary
    print_summary(results)
    
    print(f"\n{Colors.OKGREEN}{SPARKLES} Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}\n")

if __name__ == "__main__":
    main()
