
import json
from datetime import datetime, timezone
from botocore.exceptions import ClientError, ProfileNotFound

import boto3
import argparse

### Event Name: ImportImage
# KEY: AKIA2CUNLIT2UQXWJIWF
# User: jenkins
# Your Jenkins CI/CD system (running on a server at IP 80.74.109.2) automatically imported 
# a VM image (jenkins_rpm_repo_14.03.00.000.03_REV_134972.vmdk) from an S3 bucket to create
# a new AMI in AWS. As part of this import, AWS automatically created an EBS snapshot — 
# that’s the one you saw: Created by AWS-VMImport service for import-ami-2849f526756d7ac3t.
# This is expected and normal behavior when using aws ec2 import-image.
# aws ec2 import-image --disk-container file://jenkins_rpm_repo_14.03.00.000.03_REV_134972.vmdk --region us-east-1
# 
# When Would a Volume Be Created?
# aws ec2 run-instances --image-id ami-0abcd1234 --instance-type t3.micro
# 	
# AutoScaling group: eks-karptst1_be_krpntr-2025103015362125590000001a-94cd1ae1-a340-0ad6-72d7-c5faad4bd82d
# Created: Thu Oct 30 2025 17:36:59 GMT+0200
# AMI-ID: ami-0b38c2b75dde48ee1

# vol-0b0a1f7873bd875ba
# ItTag_Creator: arn:aws:sts::692859913461:assumed-role/AmazonEKS_EBS_CSI_DriverRole_dish1309_be/1759755244607037979

# reason 1 - pvc
# vol-0bfab57594ba0fbe0 last_attached_instance=i-09a883f482e58bec6 event=DetachVolume time=2025-09-17T16:03:24Z
# InstanceExists=false InstanceStackPrefix=none VolumeTags=CSIVolumeName=pvc-f450fc14-8a96-4508-9304-3f0f6ef01836,
# ebs.csi.aws.com/cluster=true,kubernetes.io/created-for/pvc/name=flowfile-repository-telaviv-adminapp-be-nifi-chart-0,
# kubernetes.io/created-for/pv/name=pvc-f450fc14-8a96-4508-9304-3f0f6ef01836,
# kubernetes.io/created-for/pvc/namespace=production,
# ItTag_Creator=arn:aws:sts::692859913461:assumed-role/AmazonEKS_EBS_CSI_DriverRole_test1309_be/1758102519601602489,
# ItTag_CreateTime=2025-09-17T10:00:11Z,map-migrated=migNMXNU4M7L7

# kubectl get sc
# kubectl get sc gp3 -o yaml

# kubectl get sc
#NAME            PROVISIONER             RECLAIMPOLICY   VOLUMEBINDINGMODE      ALLOWVOLUMEEXPANSION   AGE
#gp2             kubernetes.io/aws-ebs   Delete          WaitForFirstConsumer   false                  45d
#gp3 (default)   kubernetes.io/aws-ebs   Delete          WaitForFirstConsumer   true                   45d

# [root@QAJenkinsslave ~]# kubectl get sc gp3 -o yaml
# allowVolumeExpansion: true
# apiVersion: storage.k8s.io/v1
# kind: StorageClass
# metadata:
#   annotations:
#     storageclass.kubernetes.io/is-default-class: "true"
#   creationTimestamp: "2025-09-18T11:03:46Z"
#   name: gp3
#   resourceVersion: "2633325"
#   uid: ef0c2bca-44a9-4b6a-99d8-2d68dd606dea
# parameters:
#   fsType: ext4
#   tagSpecification_1: StackPrefix=cd130906
#   tagSpecification_2: eksClusterName=cd130906_be
#   tagSpecification_3: Owner=ReleaseManagement
#   tagSpecification_4: CreatedBy=jenkins-AlaaOdeh
#   type: gp3
# provisioner: kubernetes.io/aws-ebs
# reclaimPolicy: Delete
# volumeBindingMode: WaitForFirstConsumer


# kubectl get sc gp2 -o yaml
# apiVersion: storage.k8s.io/v1
# kind: StorageClass
# metadata:
#   annotations:
#     kubectl.kubernetes.io/last-applied-configuration: |
#       {"apiVersion":"storage.k8s.io/v1","kind":"StorageClass","metadata":{"annotations":{},"name":"gp2"},"parameters":{"fsType":"ext4","type":"gp2"},"provisioner":"kubernetes.io/aws-ebs","volumeBindingMode":"WaitForFirstConsumer"}
#   creationTimestamp: "2025-09-18T10:57:37Z"
#   name: gp2
#   resourceVersion: "280"
#   uid: e0d019b1-4248-4a17-939a-6ecbe31f94d9
# parameters:
#   fsType: ext4
#   type: gp2
# provisioner: kubernetes.io/aws-ebs
# reclaimPolicy: Delete
# volumeBindingMode: WaitForFirstConsumer

# kubect get pv
#kubectl get pv
# NAME                                       CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS   CLAIM                                                                                                                       STORAGECLASS   VOLUMEATTRIBUTESCLASS   REASON   AGE
# pvc-001bbad2-20a6-44af-a1ed-661b1e5637fa   150Gi      RWO            Delete           Bound    production/export-cs-minio-minio-chart-3                                                                                    gp3            <unset>                          45d
# pvc-04f389dd-e09a-4bda-a587-32173cafb8ca   1Gi        RWO            Delete           Bound    production/config-data-telaviv-adminapp-be-nifi-chart-0                                                                     gp3            <unset>                          35d
# pvc-091587fd-4878-4b53-b9aa-873ef7b26d22   10Gi       RWO            Delete           Bound    production/data-monitoring-tools-elasticsearch-chart-data-0                                                                 gp3            <unset>                          45d
# pvc-09fd0313-087b-4fa8-b17d-a10035b2f852   10Gi       RWO            Delete           Bound    production/flowfile-repository-telaviv-adminapp-be-nifi-chart-0                                                             gp3            <unset>                          35d
# pvc-17f6611e-6005-4807-9b76-518e4f6485e6   5Gi        RWO            Delete           Bound    production/alertmanager-telaviv-monitoring-tools-p-alertmanager-db-alertmanager-telaviv-monitoring-tools-p-alertmanager-0   gp3            <unset>                          45d
# pvc-30126ddb-f793-4533-adc2-9767f75870f5   1Gi        RWO            Delete           Bound    production/data-vault-1                                                                                                     gp3            <unset>                          45d
# pvc-34fd8183-abb7-4720-87d6-41453f16b4a0   8Gi        RWO            Delete           Bound    production/data-aim-rabbitmq-0                                                                                              gp3            <unset>                          35d

# kubectl describe pv pvc-001bbad2-20a6-44af-a1ed-661b1e5637fa

# kubectl describe pv pvc-001bbad2-20a6-44af-a1ed-661b1e5637fa
# Name:              pvc-001bbad2-20a6-44af-a1ed-661b1e5637fa
# Labels:            topology.kubernetes.io/region=us-east-2
#                    topology.kubernetes.io/zone=us-east-2a
# Annotations:       pv.kubernetes.io/migrated-to: ebs.csi.aws.com
#                    pv.kubernetes.io/provisioned-by: kubernetes.io/aws-ebs
#                    volume.kubernetes.io/provisioner-deletion-secret-name:
#                    volume.kubernetes.io/provisioner-deletion-secret-namespace:
# Finalizers:        [kubernetes.io/pv-protection external-attacher/ebs-csi-aws-com]
# StorageClass:      gp3
# Status:            Bound
# Claim:             production/export-cs-minio-minio-chart-3
# Reclaim Policy:    Delete
# Access Modes:      RWO
# VolumeMode:        Filesystem
# Capacity:          150Gi
# Node Affinity:
#   Required Terms:
#     Term 0:        topology.kubernetes.io/zone in [us-east-2a]
#                    topology.kubernetes.io/region in [us-east-2]
# Message:
# Source:
#     Type:       AWSElasticBlockStore (a Persistent Disk resource in AWS)
#     VolumeID:   vol-05b4a7eacfa78733e
#     FSType:     ext4
#     Partition:  0
#     ReadOnly:   false
# Events:         <none>

default_region = "us-east-2"

def get_tag(tags, key):
    if not tags:
        return None
    for t in tags:
        if t.get("Key") == key:
            return t.get("Value")
    return None


def format_tags(tags):
    if not tags:
        return "none"
    parts = []
    for t in tags:
        k = t.get("Key")
        v = t.get("Value")
        if k is None:
            continue
        parts.append(f"{k}={v}")
    return ",".join(parts) if parts else "none"

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

def find_last_instance_from_trail(cloudtrail, volume_id, start_time=None):
    token = None
    latest_event = None
    while True:
        params = {
            "LookupAttributes": [{"AttributeKey": "ResourceName", "AttributeValue": volume_id}],
            "MaxResults": 50,
        }
        if start_time:
            params["StartTime"] = start_time
        if token:
            params["NextToken"] = token
        resp = cloudtrail.lookup_events(**params)
        for e in resp.get("Events", []):
            try:
                event = json.loads(e.get("CloudTrailEvent", "{}"))
            except json.JSONDecodeError:
                continue
            name = event.get("eventName")
            if name not in ("AttachVolume", "DetachVolume"):
                continue
            time = event.get("eventTime") or e.get("EventTime")
            if isinstance(time, str):
                try:
                    time = datetime.fromisoformat(time.replace("Z", "+00:00"))
                except ValueError:
                    time = e.get("EventTime")
            if latest_event is None or (isinstance(time, datetime) and time > latest_event[0]):
                params_req = event.get("requestParameters", {})
                params_resp = event.get("responseElements", {})
                instance_id = (
                    params_req.get("instanceId")
                    or params_resp.get("attachment", {}).get("instanceId")
                )
                if instance_id:
                    latest_event = (time if isinstance(time, datetime) else e.get("EventTime"), instance_id, name)
        token = resp.get("NextToken")
        if not token:
            break
    if latest_event:
        ts = latest_event[0].astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return latest_event[1], latest_event[2], ts
    return None, None, None


def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("-r", "--region", help="AWS region (e.g. us-east-1)")
    args = parser.parse_args()

    region = args.region or default_region or "us-east-1"
    session = boto3.Session(region_name=region)
    ec2 = session.client("ec2", region_name=region)
    cloudtrail = session.client("cloudtrail", region_name=region)

    # Start of current year in UTC
    now = datetime.now(timezone.utc)
    start_dt = datetime(now.year, 1, 1, tzinfo=timezone.utc)

    paginator = ec2.get_paginator("describe_volumes")
    pages = paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}])

    instance_tag_cache = {}

    eks_client = boto3.client("eks", region_name=region)
    # Get EKS clusters to build exclude vector
    exclude_vector = get_eks_clusters_with_stackprefix(eks_client)
    print(f"Exclude vector: {exclude_vector}")

    def get_instance_info(instance_id):
        if not instance_id:
            return None, False
        if instance_id in instance_tag_cache:
            return instance_tag_cache[instance_id]
        try:
            resp = ec2.describe_instances(InstanceIds=[instance_id])
            reservations = resp.get("Reservations", [])
            for r in reservations:
                for i in r.get("Instances", []):
                    tags = i.get("Tags")
                    spv = get_tag(tags, "StackPrefix")
                    instance_tag_cache[instance_id] = (spv, True)
                    return spv, True
            # empty results -> instance not found
            instance_tag_cache[instance_id] = (None, False)
            return None, False
        except Exception:
            instance_tag_cache[instance_id] = (None, False)
            return None, False

    for page in pages:
        for v in page.get("Volumes", []):
            #print(f"Volume: {v}")
            vol_id = v.get("VolumeId")
            vol_type = v.get("VolumeType")
            sp = get_tag(v.get("Tags"), "StackPrefix")
            ItTag_Creator = get_tag(v.get("Tags"), "ItTag_Creator")
            if sp:
                if sp not in exclude_vector:
                    print(f"DELETE {vol_id} StackPrefix={sp}")
                    #ec2.delete_volume(VolumeId=vol_id)
                else:
                    print(f"GOOD {vol_id} StackPrefix={sp}")
                continue
            if ItTag_Creator:
                #print(f"ItTag_Creator={ItTag_Creator}")
                if "AmazonEKS_EBS_CSI_DriverRole_" in ItTag_Creator:
                    found_eks_cluster = False
                    for eks_cluster in exclude_vector:
                        eks_cluster_name = "_"+eks_cluster+"_"
                        if eks_cluster_name in ItTag_Creator:
                            print(f"GOOD2 {vol_id} ItTag_Creator={ItTag_Creator} EKS Cluster={eks_cluster}")
                            found_eks_cluster = True
                    if not found_eks_cluster:
                        # delete volume
                        print(f"TODO DELETE {vol_id} VolumeTags={format_tags(v.get('Tags'))}")
                        ec2.delete_volume(VolumeId=vol_id)
                    continue
                # else:
                #     print( f"CHECK {vol_id} VolumeTags={format_tags(v.get('Tags'))}")
                # continue
            if vol_type == "gp2":
                if ItTag_Creator and "user/jenkins" in ItTag_Creator:
                    print(f"TODO DELETE gp2 {vol_id} VolumeTags={format_tags(v.get('Tags'))}")
                    ec2.delete_volume(VolumeId=vol_id)
                else:
                    print(f"GOOD gp2 {vol_id} VolumeTags={format_tags(v.get('Tags'))}")
                continue
            inst, ev, ts = find_last_instance_from_trail(cloudtrail, vol_id, start_dt)
            if inst:
                isp, exists = get_instance_info(inst)
                exists_str = "true" if exists else "false"
                if isp:
                    print(f"{vol_id} last_attached_instance={inst} event={ev} time={ts} InstanceExists={exists_str} InstanceStackPrefix={isp} VolumeTags={format_tags(v.get('Tags'))}")
                else:
                    print(f"{vol_id} last_attached_instance={inst} event={ev} time={ts} InstanceExists={exists_str} InstanceStackPrefix=none VolumeTags={format_tags(v.get('Tags'))}")
            else:
                print(f"{vol_id} last_attached_instance=unknown VolumeTags={format_tags(v.get('Tags'))}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


