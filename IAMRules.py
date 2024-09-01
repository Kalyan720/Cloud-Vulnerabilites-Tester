import boto3
from botocore.exceptions import ClientError
import pandas as pd
import asyncio
import sys

# Define color codes for console output
RESET = '\033[0m'
BRIGHT_RED = '\033[91m'
BRIGHT_GREEN = '\033[92m'
BRIGHT_CYAN = '\033[96m'
MAGENTA = '\033[35m'
YELLOW = '\033[93m'


def initialize_iam_client(aws_access_key_id, aws_secret_access_key):
    """
    Initialize and return an IAM client.

    Args:
        aws_access_key_id (str): AWS Access Key ID.
        aws_secret_access_key (str): AWS Secret Access Key.

    Returns:
        boto3.Client: IAM client.
    """
    return boto3.client(
        'iam',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )


def print_error(message):
    """Print error messages in red."""
    print(f"{BRIGHT_RED}{message}{RESET}")


def print_info(message, color=BRIGHT_CYAN):
    """Print informational messages in specified color."""
    print(f"{color}{message}{RESET}")


def list_iam_users(iam_client):
    """
    List all IAM users in the account.

    Args:
        iam_client (boto3.Client): IAM client.
    """
    try:
        paginator = iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                print_info(f"User Name: {user['UserName']}", BRIGHT_GREEN)
    except Exception as e:
        print_error(f"Error listing IAM users: {e}")


def list_attached_user_policies(iam_client):
    """
    List all IAM users and their attached managed policies.

    Args:
        iam_client (boto3.Client): IAM client.
    """
    try:
        paginator_users = iam_client.get_paginator('list_users')
        for page in paginator_users.paginate():
            for user in page['Users']:
                user_name = user['UserName']
                print_info(f"User Name: {user_name}", MAGENTA)
                paginator_policies = iam_client.get_paginator('list_attached_user_policies')
                for policy_page in paginator_policies.paginate(UserName=user_name):
                    for policy in policy_page['AttachedPolicies']:
                        print_info(f"  Policy Name: {policy['PolicyName']}, ARN: {policy['PolicyArn']}", BRIGHT_GREEN)
    except Exception as e:
        print_error(f"Error listing attached user policies: {e}")


def manage_policy(iam, user_name, policy_arn, action):
    """
    Attach or detach a policy from a user.

    Args:
        iam (boto3.Client): IAM client.
        user_name (str): IAM user name.
        policy_arn (str): ARN of the policy to attach or detach.
        action (str): 'attach' or 'detach'.
    """
    actions = {
        "attach": iam.attach_user_policy,
        "detach": iam.detach_user_policy
    }

    if action not in actions:
        print_error(f"Invalid action '{action}'. Must be 'attach' or 'detach'.")
        return

    try:
        actions[action](UserName=user_name, PolicyArn=policy_arn)
        print_info(f"{action.capitalize()} policy {policy_arn} to user {user_name}.", BRIGHT_GREEN)
    except ClientError as e:
        print_error(f"Failed to {action} policy {policy_arn}: {e}")


async def test_policy_access(iam):
    """
    Test if the user can perform an action with the attached policy.

    Args:
        iam (boto3.Client): IAM client.

    Returns:
        bool: True if the action is permitted, False otherwise.
    """
    try:
        iam.list_roles()  # Example action
        return True
    except ClientError as e:
        if 'AccessDeniedException' in str(e):
            print_info("Policy did not grant access to the action.", BRIGHT_CYAN)
        else:
            print_error(f"Error testing policy: {e}")
        return False


async def check_policy(iam_client, user_name, policy_arn):
    """
    Attach the policy, test access, and detach the policy asynchronously.

    Args:
        iam_client (boto3.Client): IAM client.
        user_name (str): IAM user name.
        policy_arn (str): ARN of the policy to check.
    """
    try:
        print_info(f"Testing policy: {policy_arn}", BRIGHT_CYAN)
        manage_policy(iam_client, user_name, policy_arn, "attach")
        if await test_policy_access(iam_client):
            print_info(f"Potential vulnerability with policy {policy_arn}.", BRIGHT_RED)
        manage_policy(iam_client, user_name, policy_arn, "detach")
    except Exception as e:
        print_error(f"An error occurred while checking policy {policy_arn}: {e}")


async def check_all_policies(iam_client, user_name, csv_file):
    """
    Check if policies from a CSV file are accessible by a specific user asynchronously.

    Args:
        iam_client (boto3.Client): IAM client.
        user_name (str): IAM user name.
        csv_file (str): Path to the CSV file containing policy ARNs.
    """
    try:
        policies_df = pd.read_csv(csv_file)
        if 'PolicyArn' not in policies_df.columns:
            print_error("CSV file must contain a 'PolicyArn' column.")
            return

        tasks = [check_policy(iam_client, user_name, policy_arn) for policy_arn in policies_df['PolicyArn']]
        await asyncio.gather(*tasks)
    except FileNotFoundError:
        print_error(f"File not found: {csv_file}")
    except pd.errors.EmptyDataError:
        print_error(f"CSV file is empty: {csv_file}")
    except pd.errors.ParserError:
        print_error(f"CSV file is improperly formatted: {csv_file}")
    except Exception as e:
        print_error(f"An error occurred: {e}")

if __name__ == "__main__":
    # Prompt user for AWS credentials
    AWS_ACCESS_KEY_ID = input(f"{BRIGHT_CYAN}Enter the Access Key ID: {RESET}")
    AWS_SECRET_ACCESS_KEY = input(f"{BRIGHT_CYAN}Enter the Secret Access Key: {RESET}")
    user_name = input(f"{BRIGHT_CYAN}Enter the user name of the role: {RESET}")
    CSV_FILE_PATH = input(f"{BRIGHT_CYAN}Enter the path to the CSV file with policy ARNs: {RESET}")

    # Initialize IAM client
    iam_client = initialize_iam_client(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

    # Run synchronous functions
    list_iam_users(iam_client)
    list_attached_user_policies(iam_client)

    # Run asynchronous tasks
    asyncio.run(check_all_policies(iam_client, user_name, CSV_FILE_PATH))
