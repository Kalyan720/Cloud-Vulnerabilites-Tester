import boto3
from botocore.exceptions import ClientError

RESET = '\033[0m'
BRIGHT_RED = '\033[91m'
BRIGHT_GREEN = '\033[92m'
BRIGHT_CYAN = '\033[96m'
MAGENTA = '\033[35m'
YELLOW = '\033[93m'


def initialize_client(service, aws_access_key_id, aws_secret_access_key):
    """Initialize and return a client for the specified AWS service."""
    return boto3.client(
        service,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )


def list_iam_users_policies(user_name, aws_access_key_id, aws_secret_access_key):
    """List all IAM user policies and check for the SecurityAudit policy."""
    try:
        iam = initialize_client('iam', aws_access_key_id, aws_secret_access_key)
        paginator_policies = iam.get_paginator('list_attached_user_policies')
        policy_found = False

        for policy_page in paginator_policies.paginate(UserName=user_name):
            for policy in policy_page['AttachedPolicies']:
                print(f"{BRIGHT_GREEN}Policy Name: {policy['PolicyName']}, Policy ARN: {policy['PolicyArn']}{RESET}")
                if policy['PolicyName'] == "SecurityAudit":
                    policy_found = True

        return policy_found

    except ClientError as e:
        print(f"{BRIGHT_RED}An error occurred: {e}{RESET}")
        return False


def SecurityAuditorPolicies(aws_access_key_id, aws_secret_access_key):
    """List IAM users, S3 buckets, EC2 instances, WAF Web ACLs, and other security aspects."""

    session = boto3.Session(aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)

    # IAM Users and Policies
    print(f"{MAGENTA}IAM Users:{RESET}")
    iam = initialize_client('iam', aws_access_key_id, aws_secret_access_key)
    paginator = iam.get_paginator('list_users')
    for page in paginator.paginate():
        for user in page['Users']:
            print(f"{BRIGHT_CYAN}User Name: {user['UserName']}{RESET}")
            list_iam_users_policies(user['UserName'], aws_access_key_id, aws_secret_access_key)

    # S3 Buckets
    print(f"{MAGENTA}S3 Buckets:{RESET}")
    s3_client = session.client('s3')
    try:
        response = s3_client.list_buckets()
        for bucket in response['Buckets']:
            print(f"{BRIGHT_CYAN}Bucket Name: {bucket['Name']}{RESET}")
    except ClientError as e:
        print(f"{BRIGHT_RED}An error occurred while listing S3 buckets: {e}{RESET}")

    # EC2 Instances
    print(f"{MAGENTA}EC2 Instances:{RESET}")
    ec2_client = session.client('ec2')
    try:
        response = ec2_client.describe_instances()
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                print(f"{BRIGHT_CYAN}Instance ID: {instance['InstanceId']}")
                print(f"Instance Type: {instance['InstanceType']}")
                print(f"State: {instance['State']['Name']}")
                print(f"Public IP: {instance.get('PublicIpAddress', 'N/A')}")
                print(f"Private IP: {instance.get('PrivateIpAddress', 'N/A')}{RESET}")
                print("------")
    except ClientError as e:
        print(f"{BRIGHT_RED}An error occurred while listing EC2 instances: {e}{RESET}")

    # WAF (Classic)
    print(f"{MAGENTA}WAF (Classic):{RESET}")
    waf_client = session.client('waf')
    try:
        response = waf_client.list_web_acls()
        for web_acl in response.get('WebACLs', []):
            print(f"{BRIGHT_CYAN}Web ACL ID: {web_acl['WebACLId']}")
            print(f"Name: {web_acl['Name']}{RESET}")
            print("------")
    except ClientError as e:
        print(f"{BRIGHT_RED}An error occurred while listing WAF Web ACLs (Classic): {e}{RESET}")

    # WAFv2
    print(f"{MAGENTA}WAFv2:{RESET}")
    wafv2_client = session.client('wafv2')
    try:
        response = wafv2_client.list_web_acls(Scope='REGIONAL')  # Use 'CLOUDFRONT' for CloudFront distributions
        for web_acl in response.get('WebACLs', []):
            print(f"{BRIGHT_CYAN}Web ACL ID: {web_acl['Id']}")
            print(f"Name: {web_acl['Name']}{RESET}")
            print("------")
    except ClientError as e:
        print(f"{BRIGHT_RED}An error occurred while listing WAF Web ACLs (WAFv2): {e}{RESET}")

    # Security Groups
    print(f"{MAGENTA}Security Groups:{RESET}")
    try:
        response = ec2_client.describe_security_groups()
        for sg in response['SecurityGroups']:
            print(f"{BRIGHT_CYAN}Security Group ID: {sg['GroupId']}")
            print(f"Name: {sg['GroupName']}")
            print(f"Description: {sg['Description']}{RESET}")
            print("------")
    except ClientError as e:
        print(f"{BRIGHT_RED}An error occurred while listing Security Groups: {e}{RESET}")

    # VPCs and Subnets
    print(f"{MAGENTA}VPCs:{RESET}")
    try:
        response = ec2_client.describe_vpcs()
        for vpc in response['Vpcs']:
            print(f"{BRIGHT_CYAN}VPC ID: {vpc['VpcId']}")
            print(f"CIDR Block: {vpc['CidrBlock']}{RESET}")
            print("------")
    except ClientError as e:
        print(f"{BRIGHT_RED}An error occurred while listing VPCs: {e}{RESET}")

    print(f"{MAGENTA}Subnets:{RESET}")
    try:
        response = ec2_client.describe_subnets()
        for subnet in response['Subnets']:
            print(f"{BRIGHT_CYAN}Subnet ID: {subnet['SubnetId']}")
            print(f"VPC ID: {subnet['VpcId']}")
            print(f"CIDR Block: {subnet['CidrBlock']}{RESET}")
            print("------")
    except ClientError as e:
        print(f"{BRIGHT_RED}An error occurred while listing Subnets: {e}{RESET}")


if __name__ == "__main__":
    AWS_ACCESS_KEY_ID = input(f"{BRIGHT_CYAN}Enter the Access Key ID: {RESET}")
    AWS_SECRET_ACCESS_KEY = input(f"{BRIGHT_CYAN}Enter the Secret Access Key: {RESET}")

    # Initialize IAM client
    initialize_client('iam', AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

    # Check for SecurityAudit policy and list other resources
    if list_iam_users_policies("User3", AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
        SecurityAuditorPolicies(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
