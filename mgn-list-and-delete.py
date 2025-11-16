#!/usr/bin/env python3
"""
List and Delete Application Migration Service (MGN) Resources
==============================================================
Lists and optionally deletes AWS Application Migration Service resources including:
- Source servers
- Applications
- Waves
- Jobs
- Launch templates created by MGN

Author: Generated Script
Usage: python3 list-and-delete-mgn.py [--region REGION] [--delete] [--auto-delete]
"""

import boto3
import argparse
from botocore.exceptions import ClientError
import sys
from typing import List, Dict
import time

# Unicode characters for better UI
CHECKMARK = "✅"
CROSS = "❌"
WARNING = "⚠️"
INFO = "ℹ️"
SPARKLES = "✨"
ROCKET = "🚀"
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
    print("║        🔄 Application Migration Service Manager 🔄           ║")
    print("║                                                              ║")
    print("║  List and delete MGN resources (servers, apps, waves, etc)   ║")
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

def list_source_servers(mgn_client):
    """List all source servers"""
    try:
        servers = []
        # Check if pagination is supported
        try:
            paginator = mgn_client.get_paginator('describe_source_servers')
            for page in paginator.paginate():
                servers.extend(page.get('items', []))
        except (KeyError, AttributeError):
            # Fallback to direct API call if pagination not supported
            response = mgn_client.describe_source_servers()
            servers.extend(response.get('items', []))
            # Handle pagination manually if needed
            next_token = response.get('nextToken')
            while next_token:
                response = mgn_client.describe_source_servers(nextToken=next_token)
                servers.extend(response.get('items', []))
                next_token = response.get('nextToken')
        return servers
    except ClientError as e:
        print_error(f"Failed to list source servers: {str(e)}")
        return []

def list_applications(mgn_client):
    """List all applications"""
    try:
        applications = []
        # MGN uses list_applications, not describe_applications
        response = mgn_client.list_applications()
        applications.extend(response.get('items', []))
        # Handle pagination manually if needed
        next_token = response.get('nextToken')
        while next_token:
            response = mgn_client.list_applications(nextToken=next_token)
            applications.extend(response.get('items', []))
            next_token = response.get('nextToken')
        return applications
    except ClientError as e:
        print_error(f"Failed to list applications: {str(e)}")
        return []

def list_waves(mgn_client):
    """List all waves"""
    try:
        waves = []
        # MGN uses list_waves, not describe_waves
        response = mgn_client.list_waves()
        waves.extend(response.get('items', []))
        # Handle pagination manually if needed
        next_token = response.get('nextToken')
        while next_token:
            response = mgn_client.list_waves(nextToken=next_token)
            waves.extend(response.get('items', []))
            next_token = response.get('nextToken')
        return waves
    except ClientError as e:
        print_error(f"Failed to list waves: {str(e)}")
        return []

def list_jobs(mgn_client):
    """List all jobs"""
    try:
        jobs = []
        # Check if pagination is supported
        try:
            paginator = mgn_client.get_paginator('describe_jobs')
            for page in paginator.paginate():
                jobs.extend(page.get('items', []))
        except (KeyError, AttributeError):
            # Fallback to direct API call if pagination not supported
            response = mgn_client.describe_jobs()
            jobs.extend(response.get('items', []))
            # Handle pagination manually if needed
            next_token = response.get('nextToken')
            while next_token:
                response = mgn_client.describe_jobs(nextToken=next_token)
                jobs.extend(response.get('items', []))
                next_token = response.get('nextToken')
        return jobs
    except ClientError as e:
        print_error(f"Failed to list jobs: {str(e)}")
        return []

def list_mgn_launch_templates(ec2_client):
    """List launch templates created by MGN"""
    try:
        templates = []
        paginator = ec2_client.get_paginator('describe_launch_templates')
        for page in paginator.paginate():
            for template in page.get('LaunchTemplates', []):
                template_id = template['LaunchTemplateId']
                template_name = template.get('LaunchTemplateName', '').lower()
                
                # Check template tags
                try:
                    template_tags_response = ec2_client.describe_tags(
                        Filters=[
                            {'Name': 'resource-id', 'Values': [template_id]},
                            {'Name': 'resource-type', 'Values': ['launch-template']}
                        ]
                    )
                    template_tags = {tag['Key']: tag['Value'] for tag in template_tags_response.get('Tags', [])}
                    
                    # MGN templates often have specific naming patterns or tags
                    # Check for common MGN indicators
                    is_mgn_template = (
                        'mgn' in template_name or 
                        'migration' in template_name or
                        'aws-mgn' in str(template_tags).lower() or
                        any('mgn' in str(k).lower() or 'mgn' in str(v).lower() 
                            for k, v in template_tags.items())
                    )
                    
                    if is_mgn_template:
                        templates.append(template)
                except ClientError:
                    # If we can't get tags, skip this template
                    continue
        return templates
    except ClientError as e:
        print_error(f"Failed to list launch templates: {str(e)}")
        return []

def mark_server_as_archived(mgn_client, server_id):
    """Mark a source server as archived (removes from active list)"""
    try:
        mgn_client.mark_as_archived(sourceServerID=server_id)
        return True
    except ClientError as e:
        error_msg = str(e).lower()
        # If already archived, that's fine
        if 'already archived' in error_msg or 'archived' in error_msg:
            return True
        print_warning(f"Could not archive server {server_id}: {str(e)}")
        return False

def delete_source_server(mgn_client, server_id, state=None):
    """Delete a source server"""
    try:
        print_info(f"Attempting to delete server {server_id} (current state: {state})...")
        
        # For DISCOVERED state servers, archive first to remove from active list
        if state and state.upper() == 'DISCOVERED':
            print_info(f"Server is in DISCOVERED state, archiving first...")
            if mark_server_as_archived(mgn_client, server_id):
                print_success(f"Server {server_id} archived successfully")
                time.sleep(1)  # Brief wait after archiving
        
        # For connected servers (not DISCOVERED/DISCONNECTED), disconnect first
        if state and state.upper() not in ['DISCOVERED', 'DISCONNECTED', 'ARCHIVED']:
            # Server is connected, disconnect first
            try:
                print_info(f"Server is connected, disconnecting {server_id} first...")
                mgn_client.disconnect_from_service(sourceServerID=server_id)
                # Wait for disconnection to complete
                max_wait = 30
                waited = 0
                while waited < max_wait:
                    time.sleep(2)
                    waited += 2
                    try:
                        response = mgn_client.describe_source_servers(
                            filters={'sourceServerIDs': [server_id]}
                        )
                        items = response.get('items', [])
                        if items:
                            server_state = items[0].get('lifeCycle', {}).get('state', '')
                            if server_state.upper() in ['DISCONNECTED', 'DISCOVERED']:
                                print_info(f"Server disconnected successfully after {waited} seconds")
                                break
                        else:
                            # Server not found, might be deleted
                            return True
                    except ClientError as e:
                        # Server might have been deleted already
                        if 'not found' in str(e).lower():
                            return True
                        pass
            except ClientError as e:
                error_msg = str(e).lower()
                if 'not connected' not in error_msg and 'disconnected' not in error_msg:
                    print_warning(f"Could not disconnect server {server_id}: {str(e)}")
                    # Try to delete anyway
                else:
                    print_info(f"Server {server_id} is already disconnected")
        
        # Delete the source server
        print_info(f"Calling delete_source_server for {server_id}...")
        mgn_client.delete_source_server(sourceServerID=server_id)
        print_success(f"Delete API call succeeded for {server_id}")
        
        # Verify deletion (wait a bit and check)
        time.sleep(2)
        try:
            response = mgn_client.describe_source_servers(
                filters={'sourceServerIDs': [server_id]}
            )
            items = response.get('items', [])
            if items:
                print_warning(f"Server {server_id} still exists after deletion (AWS cleanup may take up to 90 minutes)")
            else:
                print_success(f"Server {server_id} verified as deleted")
        except ClientError as e:
            if 'not found' in str(e).lower() or 'does not exist' in str(e).lower():
                print_success(f"Server {server_id} verified as deleted")
            else:
                print_warning(f"Could not verify deletion status for {server_id}: {str(e)}")
        
        return True
    except ClientError as e:
        error_msg = str(e).lower()
        error_code = e.response.get('Error', {}).get('Code', '')
        # If server is already deleted or doesn't exist, consider it success
        if 'not found' in error_msg or 'does not exist' in error_msg or error_code == 'ResourceNotFoundException':
            print_info(f"Server {server_id} not found (may already be deleted)")
            return True
        print_error(f"Failed to delete source server {server_id}: {error_code} - {str(e)}")
        return False

def delete_application(mgn_client, application_id):
    """Delete an application"""
    try:
        mgn_client.delete_application(applicationID=application_id)
        return True
    except ClientError as e:
        print_error(f"Failed to delete application {application_id}: {str(e)}")
        return False

def delete_wave(mgn_client, wave_id):
    """Delete a wave"""
    try:
        mgn_client.delete_wave(waveID=wave_id)
        return True
    except ClientError as e:
        print_error(f"Failed to delete wave {wave_id}: {str(e)}")
        return False

def delete_job(mgn_client, job_id):
    """Delete a job"""
    try:
        # Jobs are typically auto-deleted, but we can try to cancel if running
        mgn_client.cancel_job(jobID=job_id)
        return True
    except ClientError as e:
        # Job might already be completed or not exist
        if 'not found' in str(e).lower() or 'completed' in str(e).lower():
            return True
        print_error(f"Failed to cancel job {job_id}: {str(e)}")
        return False

def delete_launch_template(ec2_client, template_id):
    """Delete a launch template"""
    try:
        ec2_client.delete_launch_template(LaunchTemplateId=template_id)
        return True
    except ClientError as e:
        print_error(f"Failed to delete launch template {template_id}: {str(e)}")
        return False

def list_and_manage_mgn_resources(region: str, delete: bool = False, auto_delete: bool = False):
    """List and optionally delete MGN resources"""
    try:
        mgn_client = boto3.client('mgn', region_name=region)
        ec2_client = boto3.client('ec2', region_name=region)
    except Exception as e:
        print_error(f"Failed to initialize AWS clients: {str(e)}")
        return

    print_section(f"📋 Listing MGN Resources in {region}", GEAR)

    # List source servers
    print_section("🖥️  Source Servers", INFO)
    source_servers = list_source_servers(mgn_client)
    if source_servers:
        for server in source_servers:
            server_id = server.get('sourceServerID', 'Unknown')
            name = server.get('sourceProperties', {}).get('identificationHints', {}).get('hostname', 'N/A')
            state = server.get('lifeCycle', {}).get('state', 'Unknown')
            # Check if server is connected
            is_archived = server.get('isArchived', False)
            replication_status = server.get('replicationInfo', {}).get('dataReplicationInfo', {}).get('dataReplicationState', 'N/A')
            status_indicator = "🔴" if state.upper() in ['DISCOVERED', 'DISCONNECTED'] else "🟢"
            archived_indicator = "📦" if is_archived else ""
            print(f"  {status_indicator} {server_id} | {name} | State: {state} | Replication: {replication_status} {archived_indicator}")
    else:
        print_info("No source servers found")

    # List applications
    print_section("📱 Applications", INFO)
    applications = list_applications(mgn_client)
    if applications:
        for app in applications:
            app_id = app.get('applicationID', 'Unknown')
            name = app.get('name', 'N/A')
            print(f"  - {app_id} | {name}")
    else:
        print_info("No applications found")

    # List waves
    print_section("🌊 Waves", INFO)
    waves = list_waves(mgn_client)
    if waves:
        for wave in waves:
            wave_id = wave.get('waveID', 'Unknown')
            name = wave.get('name', 'N/A')
            print(f"  - {wave_id} | {name}")
    else:
        print_info("No waves found")

    # List jobs
    print_section("⚙️  Jobs", INFO)
    jobs = list_jobs(mgn_client)
    if jobs:
        # Filter to show only active/recent jobs
        active_jobs = [j for j in jobs if j.get('status', '').upper() not in ['COMPLETED', 'CANCELLED', 'FAILED']]
        if active_jobs:
            for job in active_jobs[:10]:  # Show first 10 active jobs
                job_id = job.get('jobID', 'Unknown')
                job_type = job.get('type', 'Unknown')
                status = job.get('status', 'Unknown')
                print(f"  - {job_id} | Type: {job_type} | Status: {status}")
        else:
            print_info("No active jobs found")
    else:
        print_info("No jobs found")

    # List MGN launch templates
    print_section("🚀 Launch Templates (MGN)", INFO)
    launch_templates = list_mgn_launch_templates(ec2_client)
    if launch_templates:
        for template in launch_templates:
            template_id = template.get('LaunchTemplateId', 'Unknown')
            name = template.get('LaunchTemplateName', 'N/A')
            print(f"  - {template_id} | {name}")
    else:
        print_info("No MGN launch templates found")

    # Delete operations
    if delete:
        print_section("🗑️  Deletion Operations", WARNING)
        
        if not auto_delete:
            confirm = input(f"\n{Colors.WARNING}Do you want to delete all listed MGN resources in {region}? (yes/no): {Colors.ENDC}")
            if confirm.lower() != 'yes':
                print_info("Deletion cancelled")
                return

        # Delete source servers
        if source_servers:
            # Count DISCOVERED servers
            discovered_count = sum(1 for s in source_servers 
                                 if s.get('lifeCycle', {}).get('state', '').upper() == 'DISCOVERED')
            
            print_info(f"Deleting {len(source_servers)} source server(s)...")
            if discovered_count > 0:
                print_info(f"  - {discovered_count} server(s) in DISCOVERED state will be archived first, then deleted")
            
            deleted_count = 0
            failed_count = 0
            for server in source_servers:
                server_id = server.get('sourceServerID')
                state = server.get('lifeCycle', {}).get('state', 'Unknown')
                print(f"\n{Colors.BOLD}Processing: {server_id} (State: {state}){Colors.ENDC}")
                if delete_source_server(mgn_client, server_id, state):
                    deleted_count += 1
                    print_success(f"Successfully initiated deletion for: {server_id}")
                else:
                    failed_count += 1
                    print_error(f"Failed to delete source server: {server_id}")
                time.sleep(2)  # Increased wait time for cleanup
            
            print_section("📊 Deletion Summary", SPARKLES)
            print_info(f"Total servers processed: {len(source_servers)}")
            print_success(f"Deletion initiated for: {deleted_count} server(s)")
            if failed_count > 0:
                print_error(f"Failed to delete: {failed_count} server(s)")
            print_warning("Note: Archived servers are removed from active list immediately.")
            print_warning("      Physical deletion may take up to 90 minutes while AWS completes cleanup.")

        # Delete applications
        if applications:
            print_info(f"Deleting {len(applications)} application(s)...")
            for app in applications:
                app_id = app.get('applicationID')
                if delete_application(mgn_client, app_id):
                    print_success(f"Deleted application: {app_id}")
                time.sleep(1)

        # Delete waves
        if waves:
            print_info(f"Deleting {len(waves)} wave(s)...")
            for wave in waves:
                wave_id = wave.get('waveID')
                if delete_wave(mgn_client, wave_id):
                    print_success(f"Deleted wave: {wave_id}")
                time.sleep(1)

        # Delete active jobs
        if jobs:
            active_jobs = [j for j in jobs if j.get('status', '').upper() not in ['COMPLETED', 'CANCELLED', 'FAILED']]
            if active_jobs:
                print_info(f"Cancelling {len(active_jobs)} active job(s)...")
                for job in active_jobs:
                    job_id = job.get('jobID')
                    if delete_job(mgn_client, job_id):
                        print_success(f"Cancelled job: {job_id}")
                    time.sleep(1)

        # Delete launch templates
        if launch_templates:
            print_info(f"Deleting {len(launch_templates)} launch template(s)...")
            for template in launch_templates:
                template_id = template.get('LaunchTemplateId')
                if delete_launch_template(ec2_client, template_id):
                    print_success(f"Deleted launch template: {template_id}")
                time.sleep(1)

        print_success("Deletion operations completed")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="List and delete AWS Application Migration Service (MGN) resources",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 list-and-delete-mgn.py                    # List all MGN resources
  python3 list-and-delete-mgn.py --region us-east-1  # List in specific region
  python3 list-and-delete-mgn.py --delete            # List and prompt for deletion
  python3 list-and-delete-mgn.py --delete --auto-delete  # List and auto-delete (no prompt)
        """
    )
    
    parser.add_argument(
        '--region',
        default='us-east-1',
        help='AWS region (default: us-east-1)'
    )
    
    parser.add_argument(
        '--delete',
        action='store_true',
        help='Delete the listed resources (requires confirmation unless --auto-delete is used)'
    )
    
    parser.add_argument(
        '--auto-delete',
        action='store_true',
        help='Auto-delete without confirmation (use with caution!)'
    )
    
    return parser.parse_args()

def main():
    """Main function"""
    args = parse_arguments()
    print_header()
    
    if args.auto_delete and not args.delete:
        print_error("--auto-delete requires --delete flag")
        sys.exit(1)
    
    if args.auto_delete:
        print_warning("AUTO-DELETE MODE: Resources will be deleted without confirmation!")
    
    try:
        # Test AWS credentials
        sts_client = boto3.client('sts')
        identity = sts_client.get_caller_identity()
        print_success(f"Authenticated as: {identity.get('Arn', 'Unknown')}")
        print_info(f"Account ID: {identity.get('Account', 'Unknown')}")
        
    except Exception as e:
        print_error(f"Failed to authenticate with AWS: {str(e)}")
        sys.exit(1)
    
    list_and_manage_mgn_resources(args.region, args.delete, args.auto_delete)
    
    print(f"\n{Colors.OKGREEN}{SPARKLES} Process completed{Colors.ENDC}\n")

if __name__ == "__main__":
    main()

