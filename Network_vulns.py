import google.auth
from google.oauth2 import service_account
from google.cloud import storage, compute_v1
from googleapiclient.discovery import build

# Color codes
RESET = '\033[0m'
BRIGHT_GREEN = '\033[92m'
BRIGHT_CYAN = '\033[96m'
MAGENTA = '\033[35m'
YELLOW = '\033[93m'
BRIGHT_RED = '\033[91m'

# Set the path to your service account JSON file
SERVICE_ACCOUNT_JSON = input(f"{BRIGHT_CYAN}Enter the path to your service account JSON file : ")
PROJECT_ID = input(f"{BRIGHT_CYAN}enter the project id : ")

# Authenticate using the service account
credentials = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_JSON)

# Initialize Google Cloud clients
storage_client = storage.Client(credentials=credentials, project=PROJECT_ID)
compute_client = compute_v1.InstancesClient(credentials=credentials)

# Get IAM roles for the project
def list_iam_roles(project_id):
    service = build('cloudresourcemanager', 'v1', credentials=credentials)
    policy = service.projects().getIamPolicy(resource=project_id, body={}).execute()
    print(f"{MAGENTA}IAM Roles:{RESET}")
    for binding in policy.get("bindings", []):
        print(f"{BRIGHT_GREEN}Role: {binding['role']}, Members: {binding['members']}{RESET}")

# List all storage buckets
def list_buckets():
    print(f"{MAGENTA}Storage Buckets:{RESET}")
    buckets = storage_client.list_buckets()
    for bucket in buckets:
        print(f"{BRIGHT_CYAN}Bucket Name: {bucket.name}{RESET}")

# List all VM instances
def list_instances():
    compute_service = build('compute', 'v1', credentials=credentials)
    request = compute_service.instances().aggregatedList(project=PROJECT_ID)
    response = request.execute()

    for zone, scope in response.get('items', {}).items():
        if 'instances' in scope:
            for instance in scope['instances']:
                print(f"Instance ID: {instance['id']}")
                print(f"Instance Name: {instance['name']}")
                print(f"Instance Type: {instance['machineType']}")
                print(f"Status: {instance['status']}")
                network_interfaces = instance.get('networkInterfaces', [{}])
                access_configs = network_interfaces[0].get('accessConfigs', [{}])
                print(f"Public IP: {access_configs[0].get('natIP', 'N/A')}")
                print(f"Private IP: {network_interfaces[0].get('networkIP', 'N/A')}")
                print("------")

# List all VPCs
def list_vpcs():
    print(f"{MAGENTA}VPCs:{RESET}")
    service = build('compute', 'v1', credentials=credentials)
    request = service.networks().list(project=PROJECT_ID)
    response = request.execute()

    for vpc in response.get('items', []):
        print(f"{BRIGHT_GREEN}VPC Name: {vpc['name']}")
        print(f"VPC ID: {vpc['id']}")
        print(f"Auto-create Subnetworks: {vpc['autoCreateSubnetworks']}{RESET}")
        print("------")

# List all Subnets
def list_subnets():
    print(f"{MAGENTA}Subnets:{RESET}")
    service = build('compute', 'v1', credentials=credentials)
    request = service.subnetworks().aggregatedList(project=PROJECT_ID)
    response = request.execute()

    for region, subnets_scoped_list in response['items'].items():
        if 'subnetworks' in subnets_scoped_list:
            for subnet in subnets_scoped_list['subnetworks']:
                print(f"{BRIGHT_GREEN}Subnet Name: {subnet['name']}")
                print(f"Subnet ID: {subnet['id']}")
                print(f"VPC ID: {subnet['network']}")
                print(f"CIDR Range: {subnet['ipCidrRange']}{RESET}")
                print("------")

# Main function to print the architecture
def main():
    print(f"{YELLOW}Google Cloud Architecture Components:")
    list_iam_roles(PROJECT_ID)
    list_buckets()
    list_instances()
    list_vpcs()
    list_subnets()

if __name__ == "__main__":
    main()
