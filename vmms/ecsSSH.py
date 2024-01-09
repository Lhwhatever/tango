from collections.abc import Sequence
import os
import subprocess
import time
from typing import Optional
import boto3
import logging
from mypy_boto3_ec2.client import EC2Client
from mypy_boto3_ec2.type_defs import SubnetTypeDef
from mypy_boto3_ecs.type_defs import (
        AwsVpcConfigurationTypeDef, 
        ClusterTypeDef, 
        TaskTypeDef
        )
from mypy_boto3_ecs.client import ECSClient
from config import Config
from tangoObjects import InputFile, TangoMachine


def to_dict_kv(kv_pairs) -> dict[str, str]:
    output: dict[str, str] = {}
    for kv in kv_pairs:
        if 'name' in kv and 'value' in kv:
            output[kv['name']] = kv['value']
    return output

def to_dict_tags(tags) -> dict[str, str]:
    output: dict[str, str] = {}
    for kv in tags:
        if 'key' in kv and 'value' in kv:
            output[kv['key']] = kv['value']
    return output


def timeout(command, time_out: float = 1):
    """timeout - Run a unix command with a timeout. Return -1 on
    timeout, otherwise return the return value from the command, which
    is typically 0 for success, 1-255 for failure.
    """
    # Launch the command
    p = subprocess.Popen(
        command, stdout=open("/dev/null", "w"), stderr=subprocess.STDOUT
    )

    # Wait for the command to complete
    t = 0.0
    while t < time_out and p.poll() is None:
        time.sleep(Config.TIMER_POLL_INTERVAL)
        t += Config.TIMER_POLL_INTERVAL

    # Determine why the while loop terminated
    if p.poll() is None:
        try:
            os.kill(p.pid, 9)
        except OSError:
            pass
        returncode = -1
    else:
        returncode = p.poll()
    return returncode 


class EcsSSH:
    TANGO_NAME_TAG = 'tango:name'
    LOGGER_NAME = "TangoAwsEcs"

    _SSH_PASS_FLAGS = ['sshpass', '-e']
    
    _SSH_FLAGS = [
        "-i",
        Config.SECURITY_KEY_PATH,
        "-o",
        "StrictHostKeyChecking no",
        "-o",
        "GSSAPIAuthentication no"
    ]

    def __init__(self):
        """log - logger for the instance
        connection - EC2Connection object that stores the connection
        info to the EC2 network
        instance - Instance object that stores information about the
        VM created
        """
        self.ssh_flags = EcsSSH._SSH_FLAGS
        self.ecs: ECSClient = boto3.client('ecs')
        self.ec2: EC2Client = boto3.client('ec2')
        self.log: logging.Logger = logging.getLogger(self.LOGGER_NAME)

        self.log.debug("Environ: %s", os.getenv("TANGO_ECS_CLUSTER_NAME"))
        self.cluster = self.ensureCluster(Config.ECS_CLUSTER_NAME)
        self.subnet = self.ensureSubnet(Config.ECS_SUBNET_ID)
        self.sg_id = Config.ECS_SECURITY_GROUP
        self.task_def_arn = self.ensureTaskDefinition(
                Config.ECS_TASK_DEFINITION_ARN)


    def instanceName(self, vm: TangoMachine):
        """instanceName - Constructs a VM instance name. Always use
        this function when you need a VM instance name. Never generate
        instance names manually.
        """
        return f"{Config.PREFIX}-{vm.id}-{vm.name}"

    def ensureCluster(self, cluster_name: Optional[str]) -> ClusterTypeDef:
        self.log.debug("Ensuring cluster with parameter: %s", cluster_name)
        if cluster_name is None:
            clusters = self.ecs.describe_clusters()
            if len(clusters['clusters']) == 0:
                self.log.error("Did not find default ECS cluster")
                raise Exception("No default ECS cluster")
            self.log.info("Using default ECS cluster")
        else:
            clusters = self.ecs.describe_clusters(clusters=[cluster_name])
            if len(clusters['clusters']) == 0:
                self.log.error(
                        f"Did not find ECS cluster with name %s", cluster_name)
                raise Exception(f"No ECS cluster with name {cluster_name}")
            self.log.info(f"Using ECS cluster with name %s", cluster_name)
        return clusters['clusters'][0]

    def ensureSubnet(self, subnet_id: Optional[str]) -> SubnetTypeDef:
        self.log.debug("Ensuring subnet with ID: %s", subnet_id)
        if subnet_id is None:
            subnets = self.ec2.describe_subnets(
                    Filters=[{'Name': 'default-for-az', 'Values': ['true']}]
                    )
            if len(subnets['Subnets']) == 0:
                self.log.error("Did not find default subnet")
                raise Exception("No default subnet")
            self.log.info("Using default subnet")
        else:
            subnets = self.ec2.describe_subnets(SubnetIds=[subnet_id])
            if len(subnets['Subnets']) == 0:
                self.log.error("Did not find subnet with ID %s", subnet_id)
                raise Exception(f"No subnet with ID {subnet_id}")
            self.log.info(f"Using subnet with ID {subnet_id}")
        return subnets['Subnets'][0]

    def ensureTaskDefinition(self, task_definition_arn: Optional[str]) -> str:
        if task_definition_arn is None:
            self.log.error("Task definition not specified")
            raise Exception(
                    "Task definition ARN is required but was not specified")
        return task_definition_arn

    def initializeVM(self, vm: TangoMachine) -> Optional[TangoMachine]:
        """initializeVM - Tell ECS to run a new task.
        """
        # Create the task
        self.log.debug("Initializing VM with params: %s", vm)
        self.log.debug("VM task definition ARN: %s", self.task_def_arn)
        try:
            instance_name = self.instanceName(vm)

            awsvpc_config: AwsVpcConfigurationTypeDef = {
                    'subnets': [self.subnet['SubnetId']],
                    'assignPublicIp': 'ENABLED'
                    }

            if self.sg_id is not None:
                self.log.debug(f"Using security group: {self.sg_id}")
                awsvpc_config['securityGroups'] = [self.sg_id]

            response = self.ecs.run_task(
                    cluster=self.cluster['clusterArn'],
                    count=1,
                    enableExecuteCommand=True,
                    launchType='FARGATE',
                    networkConfiguration={
                        'awsvpcConfiguration': awsvpc_config},
                    taskDefinition=self.task_def_arn,
                    clientToken=instance_name,
                    referenceId=instance_name,
                    tags=[{'key': self.TANGO_NAME_TAG, 'value': vm.name}],
                    )

            task: TaskTypeDef = response['tasks'][0]

            start_time = time.time()
            while task['lastStatus'].upper() != 'RUNNING':
                self.log.debug(
                        f"VM %s: Waiting to reach 'RUNNING' state", 
                        instance_name
                        )
                time.sleep(Config.TIMER_POLL_INTERVAL)
                elapsed_secs = time.time() - start_time
                if elapsed_secs > Config.INITIALIZEVM_TIMEOUT:
                    self.log.warn(
                            "VM %s: Did not reach 'RUNNING' state before " \
                                    + "timeout of %d", 
                            instance_name, 
                            Config.TIMER_POLL_INTERVAL
                            )
                    return None

                task = self.ecs.describe_tasks(
                        cluster=self.cluster['clusterArn'],
                        tasks=[task['taskArn']]
                        )['tasks'][0]

                if task['lastStatus'].upper() in (
                        'DEACTIVATING', 
                        'STOPPING', 
                        'DEPROVISIONING', 
                        'STOPPED'
                        ):
                    self.log.warn(
                            "VM %s: Initialization failed, killed by AWS " \
                                    + "in state %s", 
                            instance_name, 
                            task['lastStatus']
                            )
                    return None

            self.log.debug("Task info: %s", task)
            vm.domain_name = self.extract_domain_name(task)
            if vm.domain_name is None:
                self.log.warn('VM %s: No domain name!', instance_name)

            vm.ec2_id = task['taskArn']

            self.log.info(
                    'VM %s: State %s | Domain %s | ARN %s',
                    instance_name,
                    task['lastStatus'],
                    vm.domain_name,
                    vm.ec2_id
                    )
            return vm

        except Exception as e:
            self.log.warn("initializeVM Failed: %s", e)
            return None

    def waitVM(self, vm: TangoMachine, max_secs: float):
        """waitVM - Wait at most max_secs for a VM to become
        ready. Return error if it takes too long.
        """
        instance_down = 1
        instance_name = self.instanceName(vm)
        start_time = time.time()
        self.log.debug(
                "VM %s: performing nc on %s:22", instance_name, vm.domain_name)
        while instance_down:
            instance_down = subprocess.call(
                    f"nc -z {vm.domain_name} 22",
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT,
                    )

            if instance_down:
                time.sleep(Config.TIMER_POLL_INTERVAL)
                elapsed_secs = time.time() - start_time
                if elapsed_secs > max_secs:
                    self.log.error("nc timed out after %f s", elapsed_secs)
                    return -1

        self.log.info("VM %s: nc succeeded", instance_name)
        while True:
            elapsed_secs = time.time() - start_time
            if elapsed_secs > max_secs:
                self.log.error("ssh timed out after %f s", elapsed_secs)
                return -1

            ret = timeout(
                    ["ssh"] 
                    + self.ssh_flags 
                    + [f"autolab@{vm.domain_name}", "(:)"],
                    time_out=max_secs - elapsed_secs,
                    )

            self.log.debug("VM %s: ssh returned %d", instance_name, ret)

            if ret != -1 and ret != 255:
                return 0

            time.sleep(Config.TIMER_POLL_INTERVAL)

    def copyIn(self, vm: TangoMachine, inputFiles: Sequence[InputFile]):
        """copyIn - Copy input files to the VM"""
        # create a fresh input directory
        instance_name = self.instanceName(vm)
        self.log.debug(
                "VM %s: Creating a fresh input directory", instance_name)
        ret = subprocess.call(
                ["ssh"]
                + self.ssh_flags
                + [f"autolab@{vm.domain_name}",
                   "(rm -rf autolab; mkdir autolab)"]
                )

        # copy the input files to the input directory
        for file in inputFiles:
            self.log.debug("VM %s: Copying in %s", instance_name, file)
            ret = timeout(
                    ["scp"]
                    + self.ssh_flags
                    + [
                        file.localFile,
                        f"autolab@{vm.domain_name}:autolab/{file.destFile}",
                        ],
                    time_out=Config.COPYIN_TIMEOUT,
                    )
            if ret != 0:
                return ret
            self.log.info("VM %s: successfully copied %s", instance_name, file)

        return 0

    def runJob(self, vm: TangoMachine, runTimeout: int, maxOutputFileSize: int):
        instance_name = self.instanceName(vm)
        self.log.debug("VM %s: running job", instance_name)
        runcmd = f"autodriver -u {Config.VM_ULIMIT_USER_PROC} \
                -f {Config.VM_ULIMIT_FILE_SIZE} \
                -t {runTimeout} \
                -o {maxOutputFileSize} \
                autolab > output/output.log 2>&1"

        ret = timeout(
                ["ssh"] 
                + self.ssh_flags 
                + [f"autolab@{vm.domain_name}", runcmd],
                time_out=runTimeout * 2
                )
        self.log.info("VM %s: ran job with retcode %d", instance_name, ret)
        return ret

    def copyOut(self, vm: TangoMachine, destFile: str):
        """copyOut: Copy the file output on the VM to the file outputFile on the Tango host"""
        instance_name = self.instanceName(vm)
        self.log.debug("VM %s: copying out", instance_name)
        ret = timeout(
                ["scp"]
                + self.ssh_flags
                + [f"autolab@{vm.domain_name}:output/output.log", destFile],
                Config.COPYOUT_TIMEOUT
                )
        self.log.info("VM %s: copied out with retcode %d", instance_name, ret)
        return ret

    def destroyVM(self, vm: TangoMachine):
        """destroyVM - Remove a VM from the system"""
        instance_name = self.instanceName(vm)
        self.log.debug("VM %s: destroying VM", instance_name)
        if vm.ec2_id is None:
            self.log.error(
                    "VM %s: Cannot destroy VM with no task ARN", instance_name)
            return 1
        ret = self.ecs.stop_task(
                cluster=self.cluster['clusterName'],
                task=vm.ec2_id,
                )
        return ret

    def safeDestroyVM(self, vm: TangoMachine):
        return self.destroyVM(vm)

    def getVMs(self):
        arnList = self.ecs.list_tasks(cluster=self.cluster['clusterName'])
        tasks = self.ecs.describe_tasks(
                tasks=arnList['taskArns'],
                cluster=self.cluster['clusterName'],
                include=['TAGS'],
                )
        vms: list[TangoMachine] = []
        for task in tasks['tasks']:
            if 'taskArn' in task and 'tags' in task:
                vm = TangoMachine(
                        name=to_dict_tags(task['tags'])
                            .get(self.TANGO_NAME_TAG, ""),
                        ec2_id=task['taskArn'],
                        )
                self.log.debug("getVMs: Instance %s, Task ARN %s", vm.name, vm.ec2_id)
                vms.append(vm)
        return vms


    def extract_domain_name(self, task: TaskTypeDef) -> Optional[str]:
        if 'attachments' in task:
            for att in task['attachments']:
                if 'type' in att and att['type'] == 'ElasticNetworkInterface' \
                        and 'details' in att:
                    details = to_dict_kv(att['details'])
                    if 'subnetId' in details and \
                            details['subnetId'] == self.subnet['SubnetId']:
                        if 'privateDnsName' in details:
                            return details['privateDnsName']
                        if 'privateIPv4Address' in details:
                            return details['privateIPv4Address']
        return None

                    



