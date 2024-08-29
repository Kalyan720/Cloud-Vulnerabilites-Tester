import csv
import time
import sys
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Color codes
BRIGHT_RED = "\033[91m"
BRIGHT_CYAN = "\033[96m"
BRIGHT_GREEN = "\033[92m"
BRIGHT_BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Symbols
SUCCESS_ICON = "✅"
ERROR_ICON = "❌"

# Set up the necessary variables
SERVICE_ACCOUNT_FILE = input("Enter the path to JSON file: ")
SERVICE_ACCOUNT_EMAIL = input("Enter the mail id of the service account: ")
PROJECT_ID = input("Enter the project ID: ")
CSV_FILE_PATH = input("Enter the path of the CSV file: ")

# Authenticate using the service account
credentials = service_account.Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE)

# Initialize the IAM service
service = build('cloudresourcemanager', 'v1', credentials=credentials)

def read_roles_from_csv(csv_file_path):
    roles = []
    with open(csv_file_path, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            roles.append(row['Role'])
    return roles

def print_header(message, color=BRIGHT_BLUE):
    print(f"{color}{'-' * 50}")
    print(f"{color}{message.center(50)}{RESET}")
    print(f"{color}{'-' * 50}{RESET}")

def print_footer(message, color=BRIGHT_BLUE):
    print(f"{color}{'-' * 50}")
    print(f"{color}{message.center(50)}{RESET}")
    print(f"{color}{'-' * 50}{RESET}")

def print_message(message, style=BRIGHT_CYAN):
    print(f"{style}{message}{RESET}")

def print_progress():
    for i in range(10):
        sys.stdout.write(f"\rProgress: [{'#' * i}{'.' * (10 - i)}] {i * 10}%")
        sys.stdout.flush()
        time.sleep(0.5)
    print()  # Move to the next line after progress

def assign_role_to_service_account(project_id, service_account_email, roles):
    retry_attempts = 5
    print_header("Starting Role Assignment")
    for role_name in roles:
        attempt = 0
        while attempt < retry_attempts:
            try:
                # Get the current IAM policy
                policy = service.projects().getIamPolicy(resource=project_id, body={}).execute()

                # Define the new binding
                new_binding = {
                    'role': role_name,
                    'members': [f'serviceAccount:{service_account_email}']
                }

                # Check if the role is already assigned
                role_exists = False
                for binding in policy.get('bindings', []):
                    if binding['role'] == role_name:
                        if f'serviceAccount:{service_account_email}' in binding['members']:
                            print_message(f"Service account already has the role: {role_name}", BRIGHT_CYAN)
                            role_exists = True
                        else:
                            binding['members'].append(f'serviceAccount:{service_account_email}')
                        break

                # If the role does not exist, add the new binding
                if not role_exists:
                    policy['bindings'].append(new_binding)

                # Set the updated IAM policy
                service.projects().setIamPolicy(resource=project_id, body={'policy': policy}).execute()
                print_message(f"{SUCCESS_ICON} Successfully assigned role '{role_name}' to service account '{service_account_email}'.", BRIGHT_GREEN)
                break  # Exit the retry loop on success

            except HttpError as e:
                if e.resp.status == 409:  # Conflict error
                    print_message(f"{ERROR_ICON} It can't be assigned '{role_name}': {e}", BRIGHT_RED)
                    attempt += 1
                    wait_time = 2 ** attempt  # Exponential backoff
                    print_message(f"Retrying in {wait_time} seconds...", BRIGHT_RED)
                    time.sleep(wait_time)
                else:
                    print_message(f"{ERROR_ICON} It can't be assigned '{role_name}': {e}", BRIGHT_RED)
                    break  # Exit the retry loop on non-conflict errors

    print_footer("Role Assignment Completed")

# Read roles from the CSV file
roles = read_roles_from_csv(CSV_FILE_PATH)

# Call the function with the given inputs
assign_role_to_service_account(PROJECT_ID, SERVICE_ACCOUNT_EMAIL, roles)
