# Databricks notebook source
# MAGIC %md
# MAGIC
# MAGIC ### **Trending-Based Rules (Intelligent Predictive Alerts)** 
# MAGIC <img src="https://raw.githubusercontent.com/DavidWells-DB/Suspicious-User-Activity-Demo/master/Images/DetectionFramework4.png" />
# MAGIC
# MAGIC These rules analyze trends over time to detect potential threats. They may alert on a gradual increase in network traffic to a certain server, even if the traffic at any given time doesn't exceed a specific threshold. The ability to analyze and interpret trends in data is required for this type of rule.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Detection Rule #2023.204
# MAGIC #### Suspicious User Document Access Activity
# MAGIC
# MAGIC ### Description
# MAGIC
# MAGIC This alert, termed as "Statistically Significant Document Access Volume Alert", is designed to monitor and identify anomalous user behavior in terms of document access within an organization. It leverages statistical analysis to compare a user's document access volume for the current day against their historical average.
# MAGIC
# MAGIC The alert triggers when a user's document access volume for the day significantly exceeds their historical average, as determined by a z-score threshold. A z-score is a statistical measure that describes a value's relationship to the mean of a group of values. A high z-score for a user's document access volume indicates that the number of documents they have accessed is unusually high compared to their normal behavior.
# MAGIC
# MAGIC This alert is particularly useful in identifying potential data exfiltration or other suspicious activities that involve high-volume document access. It serves as a proactive measure to ensure data security and integrity within the organization
# MAGIC
# MAGIC ### Goal
# MAGIC
# MAGIC The goal of this alert is to identify users who have accessed a statistically significant number of documents today compared to their historical average. This could be an indication of unusual activity, such as data exfiltration, insider threat, or a user preparing to leave the company.
# MAGIC
# MAGIC ### Categorization
# MAGIC
# MAGIC This alert falls under the category of User Behavior Analytics (UBA). It uses statistical analysis to identify deviations from normal behavior.
# MAGIC
# MAGIC ### Strategy Abstract
# MAGIC
# MAGIC The alert uses a z-score-based method to identify users whose document access volume for the current day significantly deviates from their historical average. The z-score is a measure of how many standard deviations an observation is from the mean. A high z-score indicates a significant deviation from the mean.
# MAGIC
# MAGIC ### Technical Context
# MAGIC
# MAGIC The alert is implemented using PySpark, a big data processing framework. It operates on a DataFrame that contains document access events, with each event having a user ID and a timestamp. The alert groups the events by user and day, calculates the mean and standard deviation of the document access volume for each user, and then calculates a z-score for the current day's document access volume.
# MAGIC
# MAGIC ### Blind Spots and Assumptions
# MAGIC
# MAGIC This alert assumes that the document access volume for each user follows a normal distribution. If this assumption is not met, the z-score may not be a reliable indicator of unusual activity. The alert also assumes that the data is complete and accurate. If there are missing or incorrect document access events, the alert may produce false positives or false negatives.
# MAGIC
# MAGIC ### False Positives
# MAGIC
# MAGIC The alert may produce false positives if a user's document access volume naturally varies a lot from day to day, or if there are temporary factors that cause a user to access more documents than usual (e.g., a large project or event). To reduce false positives, the alert includes a minimum window size and a minimum number of events threshold.
# MAGIC
# MAGIC ### Validation
# MAGIC
# MAGIC The alert can be validated by investigating the document access events for the users identified by the alert. This could involve checking the content of the accessed documents, looking for other signs of unusual activity, or speaking with the user to understand why they accessed so many documents.
# MAGIC
# MAGIC ### Priority
# MAGIC
# MAGIC The priority of this alert depends on the potential impact of the activity it detects. If the accessing of a large number of documents could lead to significant data loss or other harm to the organization, then the alert should be a high priority. However, if the potential impact is low, then the alert could be a lower priority.
# MAGIC
# MAGIC ### Response
# MAGIC
# MAGIC This alert will be validated by [2.1 Investigate Suspicious User Activity](https://sfe.cloud.databricks.com/?o=1657683783405196#notebook/3561244012033889). The SOC will be notified if the investigation detects suspicious activity.
# MAGIC
# MAGIC ### MITE ATT&CK Techniques
# MAGIC * [**T1083** - _File and Directory Discovery_](https://attack.mitre.org/techniques/T1083/): This technique involves an adversary trying to figure out the structure of the file system for further exploitation. A sudden increase in document access could be a sign that an adversary is exploring the file system to understand where valuable data is stored. The alert would trigger on this unusual activity, potentially indicating the use of this technique.
# MAGIC * [**T1119** - _Automated Collection_](https://attack.mitre.org/techniques/T1119/): This technique refers to the use of automated methods to gather data. In this case, if a user is accessing a significantly higher number of documents than usual, it could be an indication that an automated collection method is being used. The alert is designed to detect such unusual spikes in document access, which could be a sign of this ATT&CK technique being employed.
# MAGIC
# MAGIC
# MAGIC #### Leading to:
# MAGIC * [**T1020** - _Automated Exfiltration_](https://attack.mitre.org/techniques/T1020/): This technique refers to the automated, scheduled transfer of information from a target network, often as a feature of the command and control framework used by an adversary. If an adversary is using automated collection (T1119) and file and directory discovery (T1083) as part of a larger strategy to exfiltrate data, the alert could potentially detect a part of this process. A significant increase in document access could be a precursor to automated exfiltration, and the alert is designed to catch such anomalies.

# COMMAND ----------

# DBTITLE 1,Load Helper Methods
# MAGIC %run "./0.0 Helper Methods"

# COMMAND ----------

# DBTITLE 1,Detect Users Accessing Suspiciously Significant Number of Sharepoint Files
df = spark.read.format('delta').load('/tmp/detection_maturity/tables/sharepoint')
df = statistically_significant_window_by_std(df, "user_id", timestamp_column="date", no_minimum_window_events=7, current_window_is_multiple_of_mean=3.0)
dbutils.jobs.taskValues.set(key = 'user', value = df.first()['user_id'])
df.display()
