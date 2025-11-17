import json
import logging
import time
import boto3
import botocore
from botocore.config import Config

# lambda function StartStopExecutor
EXCLUDE_STACK_PREFIX_TAGS = ['no131119', 'vz131508']

sample_event ={
    "version": "0",
    "id": "5325502f-8e1b-eda3-b2e0-3dce995ea040",
    "detail-type": "Scheduled Event",
    "source": "aws.events",
    "account": "692859913461",
    "time": "2025-09-17T11:52:00Z",
    "region": "us-east-2",
    "resources": [
        "arn:aws:events:us-east-2:692859913461:rule/StopEC2Instances"
    ],
    "detail": {}
}

# Setup logging
loglevel = logging.INFO
if len(logging.getLogger().handlers) > 0:
    # The Lambda environment pre-configures a handler logging to stderr. If a handler is already configured,
    # `.basicConfig` does not execute. Thus we set the level directly.
    logging.getLogger().setLevel(logging.INFO)
else:
    logging.basicConfig(level=logging.INFO)
logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s:%(message)s',
                    level=loglevel, datefmt='%Y-%m-%d %H:%M:%S')

class AnyOps:
    def __init__(self, DryRun=False):
        self.DRYFLAG = DryRun

    def _aws_connect(self, clientAPI='s3', region=None):
        _awsCli = None

        try:
            _awsCli = boto3.client(clientAPI)
        except Exception as e:
            logging.error('Failed to connect to %s, %s' % (clientAPI, e)); exit(1)

        return _awsCli

    def listASG(self, Direction):
        logging.info("List ASG")

        # Connect to AutoScaling
        awsCli = self._aws_connect(clientAPI='autoscaling')
        asgNames = []
        try:
            a = awsCli.describe_auto_scaling_groups()
            for asg in a['AutoScalingGroups']:
                #logging.info("Checking ASG: {}".format(asg))
                if Direction == 'start':
                    asgNames.append(asg['AutoScalingGroupName'])
                    continue
                # if Direction == 'stop':
                asgName = asg['AutoScalingGroupName']
                if asgName.startswith('eks-'):
                    # Extract the no131119 part
                    parts = asgName[4:].split('_')
                    if parts[0] in EXCLUDE_STACK_PREFIX_TAGS:
                        logging.info("Skipping ASG: {}".format(asgName))
                        continue
                # if asgName.startswith('eks-no131119_'):
                #     continue
                tags = asg.get('Tags', [])
                skip = False
                for tag in tags:
                    if tag['Key'] == 'StackPrefix' and tag['Value'] in EXCLUDE_STACK_PREFIX_TAGS:
                        logging.info("Skipping ASG 2: {}".format(asgName))
                        skip = True
                        break
                    if tag['Key'] == 'eks:cluster-name':
                        parts = tag['Value'].split('_')
                        if parts[0] in EXCLUDE_STACK_PREFIX_TAGS:
                            logging.info("Skipping ASG 3: {}".format(asgName))
                            skip = True
                            break
                if skip == False:
                    logging.info("Adding ASG: {}".format(asgName))
                    asgNames.append(asgName)

        except Exception as e:
            logging.error('Failed to read ASG %s' % (e)); exit(1)
            return False
        return asgNames

    def updateASG(self, ASGName=None, Direction='start'):

        if Direction == 'start':
            _conf = {'min': 0, 'max': 4, 'desired': 4}
        if Direction == 'stop':
            _conf = {'min': 0, 'max': 0, 'desired': 0}

        logging.info("Update ASG {} to be {} ".format(ASGName, Direction))

        # Connect to AutoScaling
        awsCli = self._aws_connect(clientAPI='autoscaling')

        if self.DRYFLAG:  # if dryrun, only check status
            #logging.warning("DryRun action!, no modifications made")
            a = awsCli.describe_auto_scaling_groups(
                AutoScalingGroupNames=[ASGName]
            )
            logging.info("DryRun: {} min={}, desired={}, max={}".format(
                a['AutoScalingGroups'][0]['AutoScalingGroupName'],
                a['AutoScalingGroups'][0]['MinSize'],
                a['AutoScalingGroups'][0]['DesiredCapacity'],
                a['AutoScalingGroups'][0]['MaxSize']
            ))
            return True
        # Update AutoScaling Group
        try:
            awsCli.update_auto_scaling_group(
                AutoScalingGroupName=ASGName,
                MinSize=_conf['min'],
                DesiredCapacity=_conf['desired'],
                MaxSize=_conf['max']
            )

        except Exception as e:
            logging.error('Failed to update ASG %s' % (e)); exit(1)
        return True

    def waitASGUpdate(self, ASGName=None, Direction='start'):
        if self.DRYFLAG:
            return True

        if Direction == 'start':
            _conf = {'min': 0, 'max': 4, 'desired': 4}
        if Direction == 'stop':
            _conf = {'min': 0, 'max': 0, 'desired': 0}

        # Wait for update
        _status = False
        logging.info("Waiting for ASG update (expect min={}, desired={}, max={})".format(
            _conf['min'], _conf['desired'], _conf['max']))

        while not _status:
            try:
                awsCli = self._aws_connect(clientAPI='autoscaling')
                a = awsCli.describe_auto_scaling_groups(
                    AutoScalingGroupNames=[ASGName]
                )
                logging.info(" {}: min={}, desired={}, max={}".format(
                    a['AutoScalingGroups'][0]['AutoScalingGroupName'],
                    a['AutoScalingGroups'][0]['MinSize'],
                    a['AutoScalingGroups'][0]['DesiredCapacity'],
                    a['AutoScalingGroups'][0]['MaxSize']
                ))
                if a['AutoScalingGroups'][0]['MinSize'] == _conf['min'] and a['AutoScalingGroups'][0]['DesiredCapacity'] == _conf['desired'] and a['AutoScalingGroups'][0]['MaxSize'] == _conf['max']:
                    _status = True
                    continue
            except Exception as e:
                logging.error('Failed to update ASG %s' % (e)); exit(1)
            time.sleep(2)

        # Result
        return True

    def listEC2(self, Direction):
        logging.info("List EC2")
        awsCli = self._aws_connect(clientAPI='ec2')
        
        spot_instances = []
        regular_instances = []
        
        try:
            next_token = None
            while True:
                params = {}
                if next_token:
                    params['NextToken'] = next_token
                
                response = awsCli.describe_instances(**params)
                
                for reservation in response['Reservations']:
                    for instance in reservation['Instances']:
                        instance_id = instance['InstanceId']
                        is_spot = instance.get('InstanceLifecycle') == 'spot'
                        
                        # Check if instance should be processed
                        if Direction == 'start':
                            if instance['State']['Name'] == 'running':
                                continue
                        else:  # stop
                            if instance['State']['Name'] != 'running':
                                continue
                            
                            # Check StackPrefix exclusion
                            skip = False
                            if instance.get('Tags'):
                                for tag in instance['Tags']:
                                    if tag['Key'] == 'StackPrefix' and tag['Value'] in EXCLUDE_STACK_PREFIX_TAGS:
                                        logging.info("Skipping EC2: {}".format(instance_id))
                                        skip = True
                                        break
                            if skip:
                                continue
                        # Add to appropriate list
                        if is_spot:
                            spot_instances.append(instance_id)
                            logging.info("Adding spot EC2: {}".format(instance_id))
                        else:
                            regular_instances.append(instance_id)
                            logging.info("Adding regular EC2: {}".format(instance_id))
                
                next_token = response.get('NextToken')
                if not next_token:
                    break
        except Exception as e:
            logging.error('Failed to read EC2 %s' % (e))
            return None, None

        return spot_instances, regular_instances
    
    def updateEC2(self, spot_instances=None, regular_instances=None, Direction='start'):
        awsCli = self._aws_connect(clientAPI='ec2')
        
        if self.DRYFLAG:
            logging.warning("DryRun action!, no modifications made")
            logging.info("Spot instances: {}, Regular instances: {}".format(spot_instances, regular_instances))
            return True

        if Direction == 'start':
            all_instances = (spot_instances or []) + (regular_instances or [])
            if all_instances:
                try:
                    awsCli.start_instances(InstanceIds=all_instances)
                    return True
                except Exception as e:
                    logging.error('Failed to start EC2s %s' % (e))
                    return False
            return True

        if Direction != 'stop':
            return False
        
        # Terminate spot instances
        if spot_instances:
            try:
                logging.info("Terminating {} spot instances: {}".format(len(spot_instances), spot_instances))
                awsCli.terminate_instances(InstanceIds=spot_instances)
            except Exception as e:
                logging.error('Failed to terminate spot instances %s' % (e))
                for instance in spot_instances:
                    try:
                        logging.info("Terminating spot instance: {}".format(instance))
                        awsCli.terminate_instances(InstanceIds=[instance])
                    except Exception as e:
                        logging.error('Failed to terminate spot instance %s' % (e))
                        continue
                    break
        # Stop regular instances
        if regular_instances:
            try:
                logging.info("Stopping {} regular instances: {}".format(len(regular_instances), regular_instances))
                awsCli.stop_instances(InstanceIds=regular_instances)
            except Exception as e:
                logging.error('Failed to stop regular instances %s' % (e))
                for instance in regular_instances:
                    try:
                        logging.info("Stopping regular instance: {}".format(instance))
                        awsCli.stop_instances(InstanceIds=[instance])
                    except Exception as e:
                        logging.error('Failed to stop regular instance %s' % (e))
                        continue
                    break
        return True

def lambda_handler(event, context):
    # Debug log to inspect the event structure
    logging.debug("Event received: {}".format(event))
    # print event in json format
    logging.info("Event: {}".format(json.dumps(event, indent=4)))

    # Check if the 'resources' key exists in the event
    if 'resources' not in event:
        logging.error("'resources' key is missing from the event object")
        return False
    
    try:
        executorEvent = event['resources'][0].split("/")
        logging.info("Executor event {}".format(executorEvent[1]))
    except IndexError as e:
        logging.error("Error while accessing event['resources'][0]: {}".format(e))
        return False

    actionDircton = None
    if executorEvent[1] == "StartEC2Instances":
        actionDircton = "start"
    elif executorEvent[1] == "StopEC2Instances":
        actionDircton = "stop"

    if not actionDircton:
        logging.error("Bad action requested {}".format(actionDircton))
        return False

    # Perform AWS operations
    aops = AnyOps(DryRun=False)

    asgs = aops.listASG(Direction=actionDircton)
    logging.info("ASGNames: {}".format(asgs))

    for asg in asgs:
        #logging.info("Try set action {} on {}/{} ASG {}".format(actionDircton, k, len(asgs), asg))
        aops.updateASG(ASGName=asg, Direction=actionDircton)
    for asg in asgs:
        aops.waitASGUpdate(ASGName=asg, Direction=actionDircton)

    spot_ec2s, regular_ec2s = aops.listEC2(Direction=actionDircton)
    if spot_ec2s is None and regular_ec2s is None:
        logging.error("Failed to list EC2 instances")
        return False
    logging.info("Try set action {} on EC2 instances: {} spot, {} regular".format(actionDircton, len(spot_ec2s), len(regular_ec2s)))
    if aops.updateEC2(spot_instances=spot_ec2s, regular_instances=regular_ec2s, Direction=actionDircton):
        logging.info("EC2 instances updated successfully")

    return True

# Execute only if running as a script (for testing purposes)
if __name__ == "__main__":
    filePtr = open('event.json',)
    data = json.load(filePtr)
    print(lambda_handler(data, None))
