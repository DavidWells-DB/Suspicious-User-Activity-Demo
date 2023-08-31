# Databricks notebook source
# MAGIC %md
# MAGIC
# MAGIC ### **Trending-Based Rules (Intelligent Predictive Alerts)** 
# MAGIC ![Trend-based Rules](files/Demos/detection_library/DetectionFramework11b.png)
# MAGIC
# MAGIC These rules analyze trends over time to detect potential threats. They may alert on a gradual increase in network traffic to a certain server, even if the traffic at any given time doesn't exceed a specific threshold. The ability to analyze and interpret trends in data is required for this type of rule.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Detection Rule #2023.205
# MAGIC #### Suspicious User Email Sending Activity
# MAGIC
# MAGIC ### Description
# MAGIC
# MAGIC This alert aims to monitor and identify anomalous user email activity within an organization. This alert employs statistical analysis to compare a user's email sending volume for the current day against their historical average.
# MAGIC
# MAGIC When a user's email sending volume for a specific day significantly surpasses their historical average (based on a pre-set z-score threshold), the alert triggers. The z-score is a statistical measure that quantifies a value's relationship to the mean of a group of values. A high z-score for a user's email sending volume could signify that the number of emails sent by the user is unusually high compared to their standard behavior.
# MAGIC
# MAGIC This alert plays a crucial role in identifying potential data breaches, insider threats, or other suspicious activities involving high-volume email sending. It acts as an early warning system to maintain data security and integrity within the organization.
# MAGIC
# MAGIC ### Goal
# MAGIC
# MAGIC The alert is intended to identify users who have sent a statistically significant number of emails on a particular day compared to their historical average. This could signal unusual activity, such as data exfiltration, insider threats, or a user intending to leave the organization.
# MAGIC
# MAGIC ### Categorization
# MAGIC
# MAGIC This alert falls under the User Behavior Analytics (UBA) category. It uses statistical analysis to detect deviations from standard behavior.
# MAGIC
# MAGIC ### Strategy Abstract
# MAGIC
# MAGIC The alert employs a z-score-based method to pinpoint users whose email sending volume for the day deviates significantly from their historical average. The z-score indicates how many standard deviations an observation is from the mean. A high z-score suggests a substantial deviation from the average.
# MAGIC
# MAGIC ### Technical Context
# MAGIC
# MAGIC The alert is implemented using PySpark, a big data processing framework. It operates on a DataFrame that comprises email sending events, with each event characterized by a user ID and a timestamp. The alert groups the events by user and day, calculates the mean and standard deviation of the email sending volume for each user, and then computes a z-score for the current day's email sending volume.
# MAGIC
# MAGIC ### Blind Spots and Assumptions
# MAGIC
# MAGIC The alert presumes that the email sending volume for each user follows a normal distribution. If this assumption is incorrect, the z-score might not accurately represent unusual activity. The alert also assumes that the data is complete and error-free. If there are missing or incorrect email sending events, the alert may produce false positives or false negatives.
# MAGIC
# MAGIC ### False Positives
# MAGIC
# MAGIC False positives may occur if a user's email sending volume naturally varies significantly from day to day, or if there are temporary factors that prompt a user to send more emails than usual (for instance, a large project or event). To decrease false positives, the alert includes a minimum window size and a minimum number of events threshold.
# MAGIC
# MAGIC ### Validation
# MAGIC
# MAGIC The alert can be validated by examining the email sending events for the users highlighted by the alert. This could involve reviewing the content of the sent emails, checking for other signs of unusual activity, or discussing with the user to understand why they sent so many emails.
# MAGIC
# MAGIC ### Priority
# MAGIC
# MAGIC The priority of this alert relies on the potential impact of the activity it detects. If sending a large number of emails could result in significant data loss or other harm to the organization, then the alert should be given high priority. However, if the potential impact is minimal, then the alert could be assigned a lower priority.
# MAGIC
# MAGIC ### Response
# MAGIC
# MAGIC This alert will be validated by [2.1 Investigate Suspicious User Activity](https://sfe.cloud.databricks.com/?o=1657683783405196#notebook/3561244012033889). The SOC will be notified if the investigation reveals suspicious activity.
# MAGIC
# MAGIC ### MITRE ATT&CK Techniques
# MAGIC * [**T1114.001** - _Email Collection: Local Email Collection_](https://attack.mitre.org/techniques/T1114/001/): This technique refers to the collection of emails from the local system. If an unusually high volume of emails is being sent from a user's account, it could indicate a possible compromise and local email collection. The alert is designed to detect these anomalies.
# MAGIC
# MAGIC
# MAGIC #### Leading to:
# MAGIC * [**T1048** - _Exfiltration Over Alternative Protocol_](https://attack.mitre.org/techniques/T1048/): This technique involves exfiltrating data using an alternative communication protocol or channel. If an adversary is using phishing (T1566.001) and local email collection (T1114.001) as part of a larger strategy to exfiltrate data, the alert could potentially detect part of this process. A significant increase in email sending could be a precursor to exfiltration over an alternative protocol, and the alert is designed to catch such anomalies.
# MAGIC

# COMMAND ----------

# DBTITLE 1,Load Helper Methods
# MAGIC %run "./0.0 Helper Methods"

# COMMAND ----------

# DBTITLE 1,Detect Users Sending Statistically Significant Number of Emails
df = spark.read.format('delta').load('/tmp/detection_maturity/tables/email')
df = statistically_significant_window_by_std(df, comparative_column="sender", timestamp_column="date", no_minimum_window_events=7, current_window_is_multiple_of_mean=3.0)

# Note: This method purposfully doesn't generate a result to showcase grouping detections together for the investigation notebook.
if df.count() > 0:
    dbutils.jobs.taskValues.set(key = 'sender', value = df.first()['sender'])
