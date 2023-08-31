# Databricks notebook source
# MAGIC %md
# MAGIC ## Investigation Playbook #2023.113
# MAGIC ### 2.1 Investigate Suspicious User
# MAGIC
# MAGIC #### Introduction
# MAGIC This playbook provides step-by-step instructions to investigate suspicious user activity. It facilitates the extraction of alert details, gathers user (and associated workstation) information, and analyses antivirus, DLP, and URL proxy filtering logs. Lastly, it aids in the determination of whether the user account is compromised.
# MAGIC #### Prerequisites
# MAGIC Access to the system that generates alerts about suspicious user activity.
# MAGIC Access to user and workstation data sources.
# MAGIC Access to antivirus, DLP, and URL proxy filtering logs.
# MAGIC #### Steps to Follow
# MAGIC - **Step 1**: **_Investigation Details Extraction_**:
# MAGIC In this step, we extract the user details of the alert/investigation indicating suspicious user activity.
# MAGIC Identify the alert triggered by the security system indicating suspicious user activity.
# MAGIC Extract all relevant details of this alert, such as timestamp, user details, event details, etc.
# MAGIC Record these details as they will be used in the subsequent steps of the investigation.
# MAGIC - **Step 2**: **_User and Workstation Information Collection_**: 
# MAGIC This step involves gathering detailed information about the suspected user and their associated workstations.
# MAGIC Using the user details obtained from the alert, retrieve the comprehensive user profile from the relevant data sources.
# MAGIC Identify all workstations associated with this user. Gather and record details like workstation ID, IP address, last login time, etc.
# MAGIC - **Step 3**: **_Log Analysis_**:
# MAGIC This step will check antivirus DLP and URL proxy filtering logs against the user/workstation details.
# MAGIC Retrieve the antivirus logs for the identified user/workstations within the relevant timeframe based on the alert timestamp.
# MAGIC Extract DLP logs for the user/workstations. Look for any anomalies or suspicious activities.
# MAGIC Access URL proxy filtering logs to review the user's web activity from their associated workstations. Identify any malicious or suspicious URLs accessed.
# MAGIC - **Step 4**: **_Determination of User Compromise_**: 
# MAGIC Based on the gathered information, this step assesses if the user has been compromised.
# MAGIC Evaluate the user's activity based on the alert details, user/workstation information, and logs examined.
# MAGIC If any suspicious activity, such as unauthorized access, suspicious data transfers, accessing malicious URLs, etc., is found, determine that the user is compromised.
# MAGIC If no such activity is identified, conclude that the user is not compromised.
# MAGIC #### Conclusion
# MAGIC Follow these steps sequentially to investigate suspicious user activity effectively. This playbook aims to identify potential security threats quickly and prevent damage by taking necessary action swiftly.
# MAGIC
# MAGIC _Note: Conduct a thorough review and comply with privacy and security regulations during the investigation._

# COMMAND ----------

# MAGIC %md
# MAGIC ### Updates
# MAGIC
# MAGIC ##### July 11, 2023
# MAGIC Updated to include large outbound email detection
# MAGIC
# MAGIC ##### July 2, 2023
# MAGIC Initial creation of notebook

# COMMAND ----------

# DBTITLE 1,Load Helper Methods
# MAGIC %run "../0.0 Prep/0.0 Helper Methods"

# COMMAND ----------

# DBTITLE 1,Load Widgets
# Load the widgets
dbutils.widgets.text("User", defaultValue="", label="User ID")

# COMMAND ----------

# MAGIC %md
# MAGIC ### **Step 1**: **_User Details Extraction_**
# MAGIC
# MAGIC In this stage, our primary objective is to identify and pull out all the crucial details related to the alert, which signifies suspicious user activity. We'll focus on gathering specifics like the timestamp of the alert, event details, and most importantly, the user details. This gathered data will provide us with an initial understanding of the situation and will be used in subsequent stages of our investigation. As you'll see in the code below, we interact with our alerting system, identify the triggered alert, and extract the necessary information.

# COMMAND ----------

# Get the user ID from either the task, or from the widget
user = None

# If the widget doesn't have a user defined
if user is None or user == "":
    try:
        user = dbutils.jobs.taskValues.get(taskKey = "Investigate_Suspicious_Sharepoint_Activity", key = "user", debugValue = "DEBUG_UNDEFINED")
    except ValueError:
        print("Error: no task value to pull from job")
        user=None

if user == None or user == "":
    try:
        user = dbutils.jobs.taskValues.get(taskKey = "Suspicious_Number_Of_Emails_Sent_By_Employee", key = "sender", debugValue = "DEBUG_UNDEFINED")
    except ValueError:
        print("Error: no task value to pull from job")
        user=None

# If the user is not defined, try the widget 
if user is None or user=="DEBUG_UNDEFINED" or user == "":
    user = dbutils.widgets.get("User")


if user is None or user=="DEBUG_UNDEFINED" or user == "":
    print("ERROR: No username")
    raise Exception("Error: No username passed to notebook.")

print("---------------------------------------")
print(f"The user being investigated in this notebook is '{user}'")
print("---------------------------------------")

# COMMAND ----------

# MAGIC %md
# MAGIC ### **Step 2:** **_User and Workstation Information Collection_**
# MAGIC
# MAGIC The second stage delves deeper into the details of the user under suspicion and their associated workstations. The code in this cell interacts with the appropriate data sources to retrieve a comprehensive profile of the user in question. Additionally, we identify all workstations that this user has used. The data points like workstation ID, IP address, and last login time will be gathered and recorded for further analysis.

# COMMAND ----------

# DBTITLE 1,Collect User, Workstation and Department Data
# Get Active Directory table data
user_logins = spark.read.format('delta').load('/tmp/detection_maturity/tables/user_logins')
user_logins = filter_by_relative_time(user_logins, weeks=1, time_column="date")
workday_user_data = spark.read.format('delta').load('/tmp/detection_maturity/tables/workday') 

# Filter all logons with the user
user_logins = filter_column_by_value(user_logins, "user_id", user)

# Get the unique hosts for this user 
user_logins = user_logins.select(F.col('dest_hostname'), F.col("src_ip")).distinct()

# Extract the data into variables
user_hosts = [row['dest_hostname'] for row in user_logins.collect()]
user_ips = [row['src_ip'] for row in user_logins.collect()]
user_department_data = filter_column_by_value(workday_user_data, "employee", user)
user_department = user_department_data.first()['department']
user_title = user_department_data.first()['title']

print("---------------------------------------")
print(f"User '{user}' is a '{user_title}' in the '{user_department}' department.")
print(f"The user has accessed the following hosts {user_hosts} with IPs {user_ips} in the past seven days")
print("---------------------------------------")

# COMMAND ----------

# MAGIC %md
# MAGIC ### **Step 3:** **_Log Analysis: Antivirus_**
# MAGIC
# MAGIC In the third stage, we aim to investigate the **_antivirus_**, DLP, and URL proxy filtering logs corresponding to the identified user and workstations. We start by extracting the antivirus logs within the relevant timeframe based on the alert timestamp. Subsequently, we look into the DLP logs for any anomalies or suspicious activities. Lastly, we review the URL proxy filtering logs to identify any malicious or suspicious URLs accessed by the user. This step requires careful examination, as it can help pinpoint any potential security threats.

# COMMAND ----------

# DBTITLE 1,Check Antivirus Logs
# If there are no hostnames associated with this user, there will be no antivirus logs, so skip
antivirus_user_risk = None
antivirus_message = ""
if len(user_hosts) == 0:
    print("---------------------------------------")
    print("No hostname to associate antivirus logs with.")
    print("---------------------------------------")
else:
    antivirus = spark.read.format('delta').load('/tmp/detection_maturity/tables/antivirus')
    antivirus = filter_by_relative_time(antivirus, weeks=1, time_column="time")
    user_av = filter_columns_by_values(antivirus, filters={"hostname": user_hosts}, is_and_operator=False)
    user_malware_found = filter_column_by_value(user_av, "event_type", value="MALWAREPROTECTION_MALWARE_DETECTED")
    user_malware_cleaned = filter_column_by_value(user_av, "event_type", "MALWAREPROTECTION_MALWARE_ACTION_TAKEN")
    user_malware_cleaned = filter_column_by_value(user_av, "event_type", "MALWAREPROTECTION_MALWARE_ACTION_FAILED")
    print("---------------------------------------")
    if user_av.count() == 0:
        antivirus_message = "No antivirus events identified."
    elif user_malware_found.count() > 0:
        antivirus_message = f"User has been associated with hosts that have had {user_malware_found.count()} detected malware events in the past seven days with {user_malware_cleaned.count()} successful clean events."

        if user_malware_found.count() > 5 or user_malware_cleaned.count() > 0 or (user_malware_found.count() > user_malware_cleaned.count()):
            # High number of malware detections or less detections than cleans. High risk
            antivirus_user_risk = "High"
            reason = "of the high number of antivirus detections" if user_malware_found.count() > 5 else (" malware could not be cleaned" if user_malware_cleaned.count() > 0 else "malware detected but not removed")
            antivirus_message = "High risk associated with this user because " + reason
        elif user_malware_found.count() > 3:
            # Medium number of malware events detected in the last 7 days. Medium risk
            antivirus_message = "Medium risk associated with this user because all viruses cleaned and not at significant threshold."
            antivirus_user_risk = "Medium"
        else:
            # Low number of viruses found. Low risk
            antivirus_message = "Low risk associated with this user because all viruses cleaned and at low threshold."
            antivirus_user_risk = "Low"

print(antivirus_message)
print("---------------------------------------")
user_av.display()

# COMMAND ----------

# MAGIC %md
# MAGIC ### **Step 3:** **_Log Analysis: DLP_**
# MAGIC
# MAGIC In the third stage, we aim to investigate the antivirus, **_DLP_**, and URL proxy filtering logs corresponding to the identified user and workstations. We start by extracting the antivirus logs within the relevant timeframe based on the alert timestamp. Subsequently, we look into the DLP logs for any anomalies or suspicious activities. Lastly, we review the URL proxy filtering logs to identify any malicious or suspicious URLs accessed by the user. This step requires careful examination, as it can help pinpoint any potential security threats.

# COMMAND ----------

# DBTITLE 1,Check DLP Logs
# Load DLP Logs
dlp = spark.read.format('delta').load('/tmp/detection_maturity/tables/dlp')
dlp = filter_by_relative_time(dlp, weeks=1, time_column="timestamp")

#Find all unblocked medium+ events that DLP has identified
dlp_unblocked = filter_columns_by_values(dlp, {"user": user, "action": "Allowed"}, is_and_operator=True)

# Cate
dlp_high_unblocked = filter_column_by_category(dlp_unblocked, "risk", "High")
dlp_medium_unblocked = filter_column_by_category(dlp_unblocked, "risk", "Medium")
dlp_low_unblocked = filter_column_by_category(dlp_unblocked, "risk", "Low")

# Set the user's DLP risk
dlp_user_risk = None
dlp_user_message = ""
print("---------------------------------------")
if dlp_high_unblocked.count() > 0 or dlp_medium_unblocked.count() > 10 or dlp_low_unblocked.count() > 100:
    dlp_user_message = f"User {user} has {dlp_high_unblocked.count()} high risk DLP events, and {dlp_medium_unblocked.count()} medium risk DLP events. This is considered a high risk."
    dlp_user_risk = "High"
elif dlp_medium_unblocked.count() > 5 or dlp_low_unblocked.count() > 50:
    dlp_user_message = f"User {user} has {dlp_medium_unblocked.count()} medium risk DLP events. This is considered a medium risk."
    dlp_user_risk = "Medium"
elif dlp_low_unblocked.count() > 50:
    dlp_user_risk = "Low"
    dlp_user_message = f"User {user} has {dlp_medium_unblocked.count()} low risk DLP events. This is considered a low risk."
print(dlp_user_message)
print("---------------------------------------")
dlp_high_unblocked.display()

# COMMAND ----------

# MAGIC %md
# MAGIC ### **Step 3:** **Log Analysis: URL Proxy Filtering**
# MAGIC
# MAGIC In the third stage, we aim to investigate the antivirus, DLP, and **_URL proxy filtering_** logs corresponding to the identified user and workstations. We start by extracting the antivirus logs within the relevant timeframe based on the alert timestamp. Subsequently, we look into the DLP logs for any anomalies or suspicious activities. Lastly, we review the URL proxy filtering logs to identify any malicious or suspicious URLs accessed by the user. This step requires careful examination, as it can help pinpoint any potential security threats.

# COMMAND ----------

# DBTITLE 1,Check URL Proxy Logs
url_filtering = spark.read.format('delta').load('/tmp/detection_maturity/tables/url_filtering')
url_filtering = filter_by_relative_time(url_filtering, weeks=1, time_column="date")

user_urls = filter_columns_by_values(url_filtering, {"ip_address": user_ips, "url_category": "Malware"})
no_unique_domains = user_urls.select(F.col('domain')).distinct().count()

url_user_risk = None
url_user_risk_message = ""
print("---------------------------------------")
if user_urls.count() > 100 and no_unique_domains > 1:
    url_user_risk_message = f"User {user} has {user_urls.count()} malware URL proxy filter events with {no_unique_domains} unique domains. This is considered a high risk."
    url_user_risk = "High"
elif user_urls.count() > 50 and no_unique_domains > 1 or no_unique_domains==1:
    url_user_risk_message = f"User {user} has {user_urls.count()} malware URL proxy filter category events with {no_unique_domains} unique domains. This is considered a medium risk."
    url_user_risk = "Medium"
else:
    url_user_risk_message = f"User {user} has {user_urls.count()} malware URL proxy filter category events with {no_unique_domains} unique domains. This is considered a low risk."
    url_user_risk = "Low"
print(url_user_risk_message)
print("---------------------------------------")
user_urls.display()

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC ### **Step 4:** **_Determination of User Compromise_**
# MAGIC
# MAGIC In our final stage, we assess the situation based on the alert details, user and workstation information, and logs examined in the previous steps. Our goal here is to determine whether the user has been compromised or not. In the cell below, you'll see code that evaluates the gathered data for any suspicious activities like unauthorized access, suspicious data transfers, or accessing malicious URLs. This cell reviews the results and makes one of three decisions:
# MAGIC 1. **_No suspicious activity detected_**: There is no suspicious activity for the user. No further action required.
# MAGIC 1. **_Suspicious activity detected_**: There is suspicious activity associated with the user. Further investigation is recommended.
# MAGIC 1. **_Malicious activity detected_**: There is malicious activity activity associated with the user. It is recommended to disable the user's account using an automated playbook.

# COMMAND ----------

# DBTITLE 1,User Compromise Investigation Logic
recommendation = "Investigate"
severity = "low"
#print("---------------------------------------")
print(f"Investigating user {user} for suspicious activity. Here are the findings:")
print(f"\tAntivirus activity risk is '{antivirus_user_risk}' with the finding '{antivirus_message}'")
print(f"\tDLP activity risk is '{dlp_user_risk}' with the finding '{dlp_user_message}'")
print(f"\tURL Proxy Filtering activity risk is '{url_user_risk}' with the finding '{url_user_risk_message}'")
if antivirus_user_risk == "High" or dlp_user_risk == "High" or url_user_risk == "High":
    high_count = 0
    high_count += 1 if antivirus_user_risk == "High" else 0
    high_count += 1 if dlp_user_risk == "High" else 0
    high_count += 1 if url_user_risk == "High" else 0
    if high_count >= 2:
        severity = "high"
        recommendation = "to disable the user immediately, quarantine all host systems and investigate further."
    elif high_count >= 1:
        severity = "medium"
        recommendation = "that a SOC analyst manually contact the user."
    else:
        recommendation = "to record the event as suspicious in the risk register for future investigations."

print("")
print("---------------------------------------------------------------------------------------------------------------------")
print(f"Conclusion: This is a {severity} severity event. It is recommended {recommendation}")
print("---------------------------------------------------------------------------------------------------------------------")
user_av.display()
dlp_high_unblocked.display()
user_urls.display()

# If the investigation produces a high-severity event, then automatically disable the user in Azure Active Directory
if severity == "high":
    dbutils.jobs.taskValues.set(key = 'user', value = user)
elif severity == "medium":
    # The SOC will review this notebook and investigate the user
    pass
else:
    # Log the event for future reference.
    pass

