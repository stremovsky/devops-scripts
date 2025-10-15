import boto3
import argparse
from botocore.exceptions import ClientError
import sys
from typing import List, Dict
import time

# python3 ./list-and-delete.py --region us-east-1 --tag-key StackPrefix --tag-value vrzn1311
# aws ec2 describe-vpcs
# aws ec2 describe-vpc-endpoints

# TODO: clean s3://tf-radcom-state-rnd/yulitest/

def get_resources_by_tag(client, resource_type: str, tag_key: str, tag_value: str, vpc_ids: List[str] = None) -> List[Dict]:
    """Generic function to get resources by tag"""
    try:
        if resource_type == 'vpc_endpoints':
            print({'Name': f'tag:{tag_key}', 'Values': [tag_value]})
            response = client.describe_vpc_endpoints(Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}])
            #response = client.describe_vpc_endpoints()
            return response.get('VpcEndpoints', [])
        
        elif resource_type == 'subnets':
            response = client.describe_subnets(Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}])
            return response.get('Subnets', [])

        elif resource_type == 'security_groups':
            response = client.describe_security_groups(Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}])
            return response.get('SecurityGroups', [])
        
        elif resource_type == 'vpc_security_groups':
            if vpc_ids:
                response = client.describe_security_groups(Filters=[{'Name': 'vpc-id', 'Values': vpc_ids}])
                return response.get('SecurityGroups', [])
            return []

        elif resource_type == 'internet_gateways':
            response = client.describe_internet_gateways(Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}])
            return response.get('InternetGateways', [])

        elif resource_type == 'route_tables':
            response = client.describe_route_tables(Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}])
            return response.get('RouteTables', [])

        elif resource_type == 'transit_gateways':
            response = client.describe_transit_gateways(Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}])
            return response.get('TransitGateways', [])
        
        elif resource_type == 'transit_gateway_attachments':
            response = client.describe_transit_gateway_attachments(Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}])
            attachments = response.get('TransitGatewayAttachments', [])
            # Exclude deleted attachments
            active_attachments = [attachment for attachment in attachments if attachment['State'] != 'deleted']
            return active_attachments
        
        elif resource_type == 'load_balancers':
            # response = client.describe_load_balancers()
            # lbs = response.get('LoadBalancers', [])
            # tagged_lbs = []
            # for lb in lbs:
            #     tags = client.describe_tags(ResourceArns=[lb['LoadBalancerArn']])['TagDescriptions']
            #     if tags and any(tag['Key'] == tag_key and tag['Value'] == tag_value for tag in tags[0]['Tags']):
            #         tagged_lbs.append(lb)
            # return tagged_lbs
            response = client.describe_load_balancers()
            lbs = response.get('LoadBalancers', [])
            tagged_lbs = []
            for lb in lbs:
                # Check if load balancer is in a tagged VPC or has the specified tag
                tags = client.describe_tags(ResourceArns=[lb['LoadBalancerArn']])['TagDescriptions']
                is_tagged = tags and any(tag['Key'] == tag_key and tag['Value'] == tag_value for tag in tags[0]['Tags'])
                is_in_tagged_vpc = vpc_ids and lb.get('VpcId') in vpc_ids
                if is_tagged or is_in_tagged_vpc:
                    tagged_lbs.append(lb)
            return tagged_lbs

        elif resource_type == 'classic_load_balancers':
            response = client.describe_load_balancers()
            lbs = response.get('LoadBalancerDescriptions', [])
            tagged_lbs = []
            for lb in lbs:
                # Check if Classic LB has the specified tag or is in a tagged VPC
                tags = client.describe_tags(LoadBalancerNames=[lb['LoadBalancerName']])['TagDescriptions']
                is_tagged = tags and any(tag['Key'] == tag_key and tag['Value'] == tag_value for tag in tags[0]['Tags'])
                is_in_tagged_vpc = vpc_ids and lb.get('VPCId') in vpc_ids
                if is_tagged or is_in_tagged_vpc:
                    tagged_lbs.append(lb)
            return tagged_lbs

        elif resource_type == 'openid_connect_providers':
            response = client.list_open_id_connect_providers()
            providers = response.get('OpenIDConnectProviderList', [])
            tagged_providers = []
            for provider in providers:
                tags = client.list_open_id_connect_provider_tags(OpenIDConnectProviderArn=provider['Arn'])['Tags']
                if any(tag['Key'] == tag_key and tag['Value'] == tag_value for tag in tags):
                    tagged_providers.append(provider)
            return tagged_providers
        
        elif resource_type == 'managed_policies':
            response = client.list_policies(Scope='Local')  # Only customer-managed policies
            policies = response.get('Policies', [])
            tagged_policies = []
            for policy in policies:
                if policy['PolicyName'].startswith(tag_value+'_') or '_'+tag_value+'_' in policy['PolicyName'] or '-'+tag_value+'-' in policy['PolicyName']:
                    tagged_policies.append(policy)
                #tags = client.list_policy_tags(PolicyArn=policy['Arn'])['Tags']
                #if any(tag['Key'] == tag_key and tag['Value'] == tag_value for tag in tags):
                #    tagged_policies.append(policy)
            return tagged_policies

        elif resource_type == 'node_groups':
            eks_client = boto3.client('eks', region_name=client.meta.region_name)
            clusters = eks_client.list_clusters()['clusters']
            print(clusters)
            tagged_clusters = []
            for cluster in clusters:
                cluster_info = client.describe_cluster(name=cluster)['cluster']
                if 'tags' in cluster_info and tag_key in cluster_info['tags'] and cluster_info['tags'][tag_key] == tag_value:
                    tagged_clusters.append(cluster_info['name'])
            clusters = tagged_clusters
            print(clusters)
            tagged_node_groups = []
            for cluster in clusters:
                print(f"checking {cluster}")
                response = client.list_nodegroups(clusterName=cluster)
                nodegroups = response.get('nodegroups', [])
                print(nodegroups)
                for nodegroup in nodegroups:
                    nodegroup_info = client.describe_nodegroup(clusterName=cluster, nodegroupName=nodegroup)['nodegroup']
                    if 'tags' in nodegroup_info and tag_key in nodegroup_info['tags'] and nodegroup_info['tags'][tag_key] == tag_value:
                        tagged_node_groups.append(nodegroup_info)
                continue             
            return tagged_node_groups

        elif resource_type == 'ec2_instances':
            response = client.describe_instances(Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}])
            instances = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    # Exclude terminated instances
                    if instance['State']['Name'] != 'terminated':
                        instances.append(instance)
            return instances

        elif resource_type == 'eks_clusters':
            response = client.list_clusters()
            clusters = response.get('clusters', [])
            tagged_clusters = []
            for cluster in clusters:
                cluster_info = client.describe_cluster(name=cluster)['cluster']
                if 'tags' in cluster_info and tag_key in cluster_info['tags'] and cluster_info['tags'][tag_key] == tag_value:
                    # Add VPC information to the cluster info
                    tagged_clusters.append(cluster_info)
                else:
                    vpc_id = cluster_info.get('resourcesVpcConfig', {}).get('vpcId', 'Not specified')
                    if vpc_id in vpc_ids:
                        print(f"This vpc {vpc_id} is in the tagged clusters")
            return tagged_clusters
        
        elif resource_type == 'elastic_ips':
            response = client.describe_addresses(Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}])
            return response.get('Addresses', [])
        
        elif resource_type == 'nat_gateways':
            response = client.describe_nat_gateways(Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}])
            return response.get('NatGateways', [])
        
        elif resource_type == 'vpcs':
            response = client.describe_vpcs(Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}])
            return response.get('Vpcs', [])
        
        elif resource_type == 'volumes':
            response = client.describe_volumes(Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}])
            return response.get('Volumes', [])

        elif resource_type == 'iam_roles':
            paginator = client.get_paginator('list_roles')
            tagged_roles = []
            for page in paginator.paginate():
                roles = page.get('Roles', [])
                for role in roles:
                    if role['RoleName'].startswith(tag_value+'_') or '_'+tag_value+'_' in role['RoleName'] or '-'+tag_value+'-' in role['RoleName']:
                        tagged_roles.append(role)
                        continue
                    #if not role['RoleName'].startswith('AWS'):  # Skip AWS-managed roles
                    #    #tagged_roles.append(role)
                    #    tags = client.list_role_tags(RoleName=role['RoleName'])['Tags']
                    #    if any(tag['Key'] == tag_key and tag['Value'] == tag_value for tag in tags):
                    #        tagged_roles.append(role)
            return tagged_roles

        elif resource_type == 'iam_policies':
            response = client.list_policies()
            policies = response.get('Policies', [])
            tagged_policies = []
            for policy in policies:
                print(policy)
                if not policy['Arn'].startswith('arn:aws:iam::aws:policy/'):  # Skip AWS-managed policies
                    tags = client.list_policy_tags(PolicyArn=policy['Arn'])['Tags']
                    if any(tag['Key'] == tag_key and tag['Value'] == tag_value for tag in tags):
                        tagged_policies.append(policy)
            return tagged_policies
        
        elif resource_type == 'network_interfaces':
            response = client.describe_network_interfaces(Filters=[{'Name': f'tag:{tag_key}', 'Values': [tag_value]}])
            return response.get('NetworkInterfaces', [])
        
        elif resource_type == 'kms_keys':
            response = client.list_aliases()
            resources = []
            for alias in response["Aliases"]:
                #print(alias)
                if alias["AliasName"].startswith("alias/eks/" + tag_value):
                    #print("Found alias:", alias)
                    resources.append(alias)
            return resources
        
        elif resource_type == "log_groups":
            response = client.describe_log_groups()
            tagged_logs = []
            #print(response)
            for group in response["logGroups"]:
                #print(group)
                #print(f"checking: '/aws/eks/{tag_value}' in {group['logGroupName']}")
                if group['logGroupName'].startswith("/aws/eks/" + tag_value):
                    #print(group)
                    tagged_logs.append(group)
            return tagged_logs

    except ClientError as e:
        print(f"Error getting {resource_type}: {e}")
        return []

def delete_resource(client, resource_type: str, resource: Dict) -> bool:
    """Generic function to delete resources"""
    try:
        if resource_type == 'security_groups' or resource_type == 'vpc_security_groups':
            client.delete_security_group(GroupId=resource['GroupId'])
        
        elif resource_type == 'subnets':
            client.delete_subnet(SubnetId=resource['SubnetId'])
        
        elif resource_type == 'route_tables':
            client.delete_route_table(RouteTableId=resource['RouteTableId'])

        elif resource_type == 'internet_gateways':
            client.delete_internet_gateway(InternetGatewayId=resource['InternetGatewayId'])

        elif resource_type == 'kms_keys':
            client.schedule_key_deletion(KeyId=resource['TargetKeyId'],
                PendingWindowInDays=7  # must be between 7 and 30
            )

        elif resource_type == 'vpc_endpoints':
            client.delete_vpc_endpoints(VpcEndpointIds=[resource['VpcEndpointId']])
        
        elif resource_type == 'transit_gateways':
            client.delete_transit_gateway(TransitGatewayId=resource['TransitGatewayId'])
        
        elif resource_type == 'transit_gateway_attachments':
            client.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=resource['TransitGatewayAttachmentId'])
        
        elif resource_type == 'classic_load_balancers':
            client.delete_load_balancer(LoadBalancerName=resource['LoadBalancerName'])

        elif resource_type == 'load_balancers':
            client.delete_load_balancer(LoadBalancerArn=resource['LoadBalancerArn'])

        elif resource_type == 'node_groups':
            eks_client = boto3.client('eks', region_name=client.meta.region_name)
            #print(f"foing to delete {resource['clusterName']} - {resource['nodegroupName']} ")
            eks_client.delete_nodegroup(clusterName=resource['clusterName'], nodegroupName=resource['nodegroupName'])

        elif resource_type == 'ec2_instances':
            client.terminate_instances(InstanceIds=[resource['InstanceId']])

        elif resource_type == 'eks_clusters':
            client.delete_cluster(name=resource['name'])
        
        elif resource_type == "log_groups":
            client.delete_log_group(logGroupName=resource["logGroupName"])

        elif resource_type == 'elastic_ips':
            client.release_address(AllocationId=resource['AllocationId'])
        
        elif resource_type == 'nat_gateways':
            client.delete_nat_gateway(NatGatewayId=resource['NatGatewayId'])
        
        elif resource_type == 'vpcs':
            client.delete_vpc(VpcId=resource['VpcId'])
        
        elif resource_type == 'volumes':
            client.delete_volume(VolumeId=resource['VolumeId'])

        elif resource_type == 'openid_connect_providers':
            client.delete_open_id_connect_provider(OpenIDConnectProviderArn=resource['Arn'])
   
        elif resource_type == 'iam_policies':
            # Detach policy from all entities first
            entities = client.list_entities_for_policy(PolicyArn=resource['Arn'])
            for role in entities['PolicyRoles']:
                client.detach_role_policy(RoleName=role['RoleName'], PolicyArn=resource['Arn'])
            for user in entities['PolicyUsers']:
                client.detach_user_policy(UserName=user['UserName'], PolicyArn=resource['Arn'])
            for group in entities['PolicyGroups']:
                client.detach_group_policy(GroupName=group['GroupName'], PolicyArn=resource['Arn'])
            # Delete all non-default versions
            versions = client.list_policy_versions(PolicyArn=resource['Arn'])['Versions']
            for version in versions:
                if not version['IsDefaultVersion']:
                    client.delete_policy_version(PolicyArn=resource['Arn'], VersionId=version['VersionId'])
            client.delete_policy(PolicyArn=resource['Arn'])
        
        elif resource_type == 'network_interfaces':
            client.delete_network_interface(NetworkInterfaceId=resource['NetworkInterfaceId'])

        elif resource_type == 'iam_roles':
            # Detach all policies from the role
            attached_policies = client.list_attached_role_policies(RoleName=resource['RoleName'])['AttachedPolicies']
            for policy in attached_policies:
                client.detach_role_policy(RoleName=resource['RoleName'], PolicyArn=policy['PolicyArn'])
            # Delete inline policies
            inline_policies = client.list_role_policies(RoleName=resource['RoleName'])['PolicyNames']
            for policy_name in inline_policies:
                client.delete_role_policy(RoleName=resource['RoleName'], PolicyName=policy_name)
            client.delete_role(RoleName=resource['RoleName'])

        elif resource_type == "managed_policies":
            client.delete_policy(PolicyArn=resource['Arn'])
        
        print(f"Deleted {resource_type}: {resource.get('Arn', resource.get('Id', resource.get('Name', str(resource))))}")
        return True
    except ClientError as e:
        print(f"Error deleting {resource_type}: {e}")
        return False

def list_and_manage_resources(tag_key: str, tag_value: str, region: str, delete: bool = False, auto_delete: bool = False) -> None:
    """Main function to list and optionally delete resources"""
    # Initialize boto3 clients with specified region
    ec2_client = boto3.client('ec2', region_name=region)
    elb_client = boto3.client('elbv2', region_name=region)
    eks_client = boto3.client('eks', region_name=region)
    iam_client = boto3.client('iam', region_name=region)  # IAM is global but accepts region for consistency
    kms_client = boto3.client("kms", region_name=region)
    log_client = boto3.client("logs", region_name=region)
    elb_classic_client = boto3.client('elb', region_name=region)

    # Get VPC IDs first to filter load balancers
    vpc_ids = [vpc['VpcId'] for vpc in get_resources_by_tag(ec2_client, 'vpcs', tag_key, tag_value)]

    resource_types = [
        ('kms_keys', kms_client),
        ('vpc_endpoints', ec2_client),
        ('transit_gateway_attachments', ec2_client),
        ('transit_gateways', ec2_client),
        ('load_balancers', elb_client),
        ('classic_load_balancers', elb_classic_client),  # Classic Load Balancers
        ('node_groups', eks_client),
        ('ec2_instances', ec2_client),
        ('elastic_ips', ec2_client),
        ('eks_clusters', eks_client),
        ('nat_gateways', ec2_client),
        ('subnets', ec2_client),
        ('route_tables', ec2_client),
        ('internet_gateways', ec2_client),
        ('security_groups', ec2_client),
        ('log_groups', log_client),
        ('volumes', ec2_client),
        ('network_interfaces', ec2_client),
        ('openid_connect_providers', iam_client),
        ('iam_roles', iam_client),
        ('managed_policies', iam_client),
        ('vpc_security_groups', ec2_client),
        ('vpcs', ec2_client),
        #('iam_policies', iam_client),
    ]

    for resource_type, client in resource_types:
        print(f"\nListing {resource_type.replace('_', ' ').title()} in region {region}:")
        resources = get_resources_by_tag(client, resource_type, tag_key, tag_value, vpc_ids)
        
        if not resources:
            print("No resources found with specified tag.")
            continue

        for resource in resources:
            resource_id = (
                         resource.get('VpcEndpointId') or
                         resource.get('InternetGatewayId') or
                         resource.get('InstanceId') or
                         resource.get('RouteTableId') or
                         resource.get('ElasticIp') or
                         resource.get('TransitGatewayAttachmentId') or
                         resource.get('NetworkInterfaceId') or
                         resource.get('TransitGatewayId') or
                         resource.get('LoadBalancerArn') or
                         resource.get('LoadBalancerName') or
                         resource.get('SecurityGroupId') or
                         resource.get('AllocationId') or
                         resource.get('NatGatewayId') or
                         resource.get('logGroupName') or
                         resource.get('AliasName') or
                         resource.get('SubnetId') or
                         resource.get('GroupId') or
                         resource.get('name') or
                         resource.get('VolumeId') or
                         resource.get('Arn') or
                         resource.get('nodegroupName') or
                         resource.get('RoleName') or
                         resource.get('VpcId') or
                         str(resource))
            
            # Special handling for EKS clusters to show VPC ID
            if resource_type == 'eks_clusters' and 'vpc_id' in resource:
                print(f"- {resource_id} (VPC ID: {resource['vpc_id']})")
            else:
                print(f"- {resource_id}")

        if auto_delete:
            for resource in resources:
                delete_resource(client, resource_type, resource)
                time.sleep(0.1)  # Add small delay between deletions
        elif delete:
            confirm = input(f"\nDo you want to delete these {len(resources)} {resource_type} in region {region}? (yes/no): ")
            if confirm.lower() == 'yes':
                for resource in resources:
                    if delete_resource(client, resource_type, resource):
                        time.sleep(0.1)  # Add small delay between deletions
            else:
                print(f"Skipping deletion of {resource_type}")

def main():
    parser = argparse.ArgumentParser(description='List and manage AWS resources by tag')
    parser.add_argument('--tag-key', required=True, help='Tag key to search for')
    parser.add_argument('--tag-value', required=True, help='Tag value to search for')
    parser.add_argument('--region', required=True, help='AWS region (e.g., us-east-1)')
    parser.add_argument('--delete', action='store_true', help='Enable deletion of found resources')
    parser.add_argument('--auto-delete', action='store_true', help='Enable deletion of found resources')
    
    args = parser.parse_args()
    
    print(f"Searching for resources with tag: {args.tag_key}={args.tag_value} in region {args.region}")
    if args.delete:
        print("WARNING: Deletion mode is enabled. You will be prompted for confirmation before any deletion.")
    
    list_and_manage_resources(args.tag_key, args.tag_value, args.region, args.delete, args.auto_delete)

if __name__ == '__main__':
    main()
