# Databricks notebook source
# MAGIC %md
# MAGIC # Response Playbook #2023.4
# MAGIC # Active Directory User Disabling Playbook
# MAGIC
# MAGIC ## Overview
# MAGIC
# MAGIC This playbook is designed to automate the process of disabling a user in Active Directory. It can be triggered either manually or automatically based on user behavior. It is primarily intended for use by security analysts.
# MAGIC
# MAGIC ## Trigger
# MAGIC
# MAGIC The playbook is triggered in two ways:
# MAGIC
# MAGIC 1. **Automatically**: Based on user behavior that meets certain predefined conditions.
# MAGIC 2. **Manually**: A security analyst can initiate the playbook as needed.
# MAGIC
# MAGIC ## Process
# MAGIC
# MAGIC The playbook follows these steps:
# MAGIC
# MAGIC 1. It pulls the user details from one of three potential sources:
# MAGIC    - The response table
# MAGIC    - Data passed across tasks in a Databricks job
# MAGIC    - A notebook widget
# MAGIC
# MAGIC 2. It connects to the Azure AD Graph API.
# MAGIC
# MAGIC 3. It disables the specified users in Active Directory.
# MAGIC
# MAGIC ## Outcome
# MAGIC
# MAGIC Upon successful execution, the specified user accounts will be disabled in Active Directory.
# MAGIC
# MAGIC ## Logging and Reporting
# MAGIC
# MAGIC The execution of this playbook is carried out in a Databricks job, which records the outcome of the notebook's run. This allows for easy tracking and auditing of the actions taken by the playbook.
# MAGIC
# MAGIC ## Risks and Cautions
# MAGIC
# MAGIC While this playbook automates a critical security function, it's essential to be aware of potential risks. Automated disabling of users can potentially impact users who shouldn't be disabled. Therefore, ensuring the accuracy of the conditions that trigger the playbook is crucial.
# MAGIC
# MAGIC ## Re-enabling Users
# MAGIC
# MAGIC If a user has been disabled in error, they can be re-enabled manually in Azure AD.
# MAGIC

# COMMAND ----------

# DBTITLE 1,Load Widget
dbutils.widgets.text("User", defaultValue="", label="User ID")

# COMMAND ----------

# DBTITLE 1,Load Azure AD Libraries
# MAGIC %pip install adal msrest msal

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC ## Step 1: Pull User Details
# MAGIC
# MAGIC The first step in this playbook is to gather the necessary user details. This information can come from one of three sources:
# MAGIC
# MAGIC 1. **Response Table**: The response table is a structured data source that contains information about users and their activities. This could include the user's ID, username, or other identifying information.
# MAGIC
# MAGIC 2. **Databricks Job Data**: If this playbook is being triggered as part of a Databricks job, it can use data passed between tasks within that job. This might include user details that have been gathered or processed by earlier tasks in the job.
# MAGIC
# MAGIC 3. **Notebook Widget**: If the playbook is being run from a Databricks notebook, it can pull user details from a notebook widget. This could be a form or other interactive element allowing users to input or select information.
# MAGIC
# MAGIC The playbook will use these details to identify the specific user or users who need to be disabled in Active Directory.

# COMMAND ----------

# DBTITLE 1,Load User from Job or Widget
# Get the user ID from either the task, or from the widget
username = None

# If the widget doesn't have a user defined
if username is None or user == "":
    try:
        username = dbutils.jobs.taskValues.get(taskKey = "Investigate_Suspicious_User", key = "user", debugValue = "DEBUG_UNDEFINED")
    except ValueError:
        print("Error: no task value to pull from job")
        username=None

# If the user is not defined, try the widget 
if username is None or username=="DEBUG_UNDEFINED" or username == "":
    username = dbutils.widgets.get("User")


if username is None or username=="DEBUG_UNDEFINED" or username == "":
    print("ERROR: No username to disable. Exit gacefully")
    exit(0)

print("---------------------------------------")
print(f"The user being disabled is '{username}'")
print("---------------------------------------")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Step 2: Connect to Azure AD Graph API and Disable User
# MAGIC
# MAGIC Once the playbook has the necessary user details, it will connect to the Azure AD Graph API. This web-based service provided by Microsoft allows for programmatic access to Azure Active Directory.
# MAGIC
# MAGIC The playbook will authenticate with the API using the necessary credentials (these should be securely stored and managed to ensure they are not exposed or compromised).
# MAGIC
# MAGIC Once connected to the API, the playbook will request to disable the specified user or users. This is done by setting the 'accountEnabled' attribute of the user object to 'false'.
# MAGIC
# MAGIC The API will respond with a status code and message indicating whether the request was successful. If the request fails, the playbook should have error handling to log the failure and alert the appropriate personnel.

# COMMAND ----------

# DBTITLE 1,Disable User in Azure AD
import requests
from msal import ConfidentialClientApplication


def disable_user(user_id):
    """
    Disables a user in Azure Active Directory using the Microsoft Graph API.
    
    Parameters:
        - user_id (str): The ID of the user to disable.
    
    Returns:
        None
    """
    # Get API Token details from Databricks Secrets Manager
    client_id = dbutils.secrets.get(scope = "DavidW", key = "Azure_Client_ID")
    client_secret = dbutils.secrets.get(scope = "DavidW", key = "Azure_App_Secret")
    tenant_id = dbutils.secrets.get(scope = "DavidW", key = "Azure_Tenant_ID")
    
    # Get the Azure API App context
    app = ConfidentialClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential=client_secret,
    )
    
    # Request a token
    result = app.acquire_token_for_client(["https://graph.microsoft.com/.default"])
    
    # Use the token to make an API request to disable the user
    if "access_token" in result:
        token = result["access_token"]
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-type' : 'application/json'
        }
        data = {
            "accountEnabled": False
        }
        response = requests.patch(f'https://graph.microsoft.com/v1.0/users/{user_id}', headers=headers, json=data)
        if response.status_code == 204:
            print(f"Successfully disabled user '{username}' (UID: '{user_id}').")
        else:
            raise ValueError(f'Could not disable user {user_id}. The API response was: {response.content}')
    else:
        # Print any error messages from requesting the API token
        print(result.get("error"))
        print(result.get("error_description"))
        print(result.get("correlation_id"))  # You may need this when reporting a bug


def disable_user_by_username(username):
    """
    Disables a user in Azure Active Directory using the Microsoft Graph API, given a username.
    
    Parameters:
        - username (str): The username of the user to disable.
    
    Returns:
        None
    """
    # Get the user GUID from the users table
    df = spark.sql(f"SELECT ID FROM delta.`/tmp/detection_maturity/tables/users` WHERE Username = '{username}'")
    
    # Disable the user by the GUID
    if df.count() > 0:
        disable_user(df.first()['ID'])
    else:
         raise ValueError(f"Invalid user '{user}' passed to Notebook.") 


# Call the disable_user_by_username function with a specific user 
disable_user_by_username(username)
