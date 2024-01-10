# Databricks notebook source
# MAGIC %md
# MAGIC ## Cyber Use Case
# MAGIC ### Detection Maturity Curve
# MAGIC <img src="https://raw.githubusercontent.com/DavidWells-DB/Suspicious-User-Activity-Demo/master/Images/DetectionFramework.png" />

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC # Cyber security Detection
# MAGIC ##### Security detection has become more sophisticated to handle an evolving threat landscape over time. These rules can vary in complexity and sophistication, from simple pattern-based to advanced machine learning-based rules. Historically, SIEM maturity framework rules evolved from reactive and deterministic to predictive and probabilistic, enhancing their ability to detect anomalies and potential threats. This progression includes pattern-based, threshold-based, statistical anomaly detection, trending-based, and machine learning-based rules, each bringing a unique approach to threat detection. However, most organizations struggle to collect all of the data within their environment, and scale their detection.
# MAGIC
# MAGIC Databricks provides advantages over traditional SIEMS:
# MAGIC 1. **Scalability**: Databricks, built on Apache Spark, can handle large volumes of data and scale effectively, which is beneficial when dealing with large amounts of security data.
# MAGIC 1. **Cost-effectiveness**: Databricks cost model allows for organizations to expand their visibility across the entire enterprise while providing advanced ML and AI capabilities.
# MAGIC 1. **Machine Learning Integration**: Databricks integrates with machine learning frameworks and has built-in support for model tracking and deployment with MLflow, enhancing its ability to detect unusual patterns that may indicate cyber threats.
# MAGIC 1. **Real-Time Analysis**: Databricks supports real-time data processing with Delta Live Tables, enabling timely detection and reaction to cyber threats.
# MAGIC 1. **Flexibility**: Databricks supports multiple languages, including Python, R, Scala, and SQL, providing flexibility to security teams.
# MAGIC 1. **Automated Model Retraining**: Databricks automates model retraining, keeping the model updated with the latest threat patterns.
# MAGIC 1. **Data Transformations**: Databricks offer various functions for data transformation, such as the convert_timezone function, which helps deal with global data.

# COMMAND ----------

# DBTITLE 1,Load Helper Methods
# MAGIC %run "./0.0 Helper Methods"

# COMMAND ----------

# DBTITLE 1,Load Data
# MAGIC %run "./0.1 Data Creation"

# COMMAND ----------

# MAGIC %md 
# MAGIC
# MAGIC ### **Pattern-Based Rules (Reactive)** 
# MAGIC <img src="https://raw.githubusercontent.com/DavidWells-DB/Suspicious-User-Activity-Demo/master/Images/DetectionFramework1.png" />
# MAGIC
# MAGIC Basic rules, searching for specific patterns or behaviors. They trigger an alert upon detecting known malicious IP addresses or sequences of commands associated with a particular type of attack.
# MAGIC
# MAGIC ### Example
# MAGIC > Find URL Filter events where the category is 'Malware' or 'Adult/Mature'.
# MAGIC
# MAGIC
# MAGIC

# COMMAND ----------

# DBTITLE 1,Detect Users Accessing Malicious URLs
df = spark.read.format('delta').load('/tmp/detection_maturity/tables/url_filtering')
df = filter_by_relative_time(df, days=1, time_column="date")
df = filter_columns_by_values(df, {"url_category": ["Malware", "Trojan"]})
df.show()

# COMMAND ----------

# MAGIC %md 
# MAGIC
# MAGIC ### **Threshold-Based Rules (Proactive)** 
# MAGIC <img src="https://raw.githubusercontent.com/DavidWells-DB/Suspicious-User-Activity-Demo/master/Images/DetectionFramework2.png" />
# MAGIC
# MAGIC These rules are more advanced, triggering an alert when a predefined limit is exceeded. An understanding of the normal operating parameters is required to set these rules, which may alert, for instance, when there are an unusual number of failed login attempts within a specified period.
# MAGIC

# COMMAND ----------

# DBTITLE 1,Detect IPs With High Number of Connections In The Past 24 Hours
df = spark.read.format('delta').load('/tmp/detection_maturity/tables/web_logs')
df = filter_by_relative_time(df, time_column="timestamp", days=1)
df = threshold_based_rule(df=df, groupby_column="ip", threshold=100)
df.display()

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC ### **Anomaly-Based Rules (Predictive)** 
# MAGIC <img src="https://raw.githubusercontent.com/DavidWells-DB/Suspicious-User-Activity-Demo/master/Images/DetectionFramework3.png" />
# MAGIC
# MAGIC These rules employ statistical methods to establish a model of normal behavior, subsequently alerting on significant deviations from this model. Techniques such as clustering, regression, or outlier detection may be utilized. These rules are probabilistic and require an advanced understanding of the data.

# COMMAND ----------

# DBTITLE 1,Detect Customer With An Anomalous Number of Files Accessed Compared To Peers
df = spark.read.format('delta').load('/tmp/detection_maturity/tables/ciam')
df = filter_by_relative_time(df, days=1, time_column="_event_date")
df = filter_columns_by_values(df, {"outcome": ["DENIED", "BLOCKED"]})
df = statistical_anomaly_detection_group_by(df, "login_id")
df.display()

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC ### **Trending-Based Rules (Intelligent Predictive Alerts)** 
# MAGIC <img src="https://raw.githubusercontent.com/DavidWells-DB/Suspicious-User-Activity-Demo/master/Images/DetectionFramework4.png" />
# MAGIC
# MAGIC These rules analyze trends over time to detect potential threats. They may alert on a gradual increase in network traffic to a certain server, even if the traffic at any given time doesn't exceed a specific threshold. The ability to analyze and interpret trends in data is required for this type of rule.

# COMMAND ----------

df = spark.read.format('delta').load('/tmp/detection_maturity/tables/sharepoint')
df_std = statistically_significant_window_by_std(df, comparative_column="user_id", timestamp_column="date", no_minimum_window_events=7, current_window_is_multiple_of_mean=3.0)
df_std.display()

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC ### **Machine Learning-Based Rules (Intelligent Predictive Alerts)** 
# MAGIC <img src="https://raw.githubusercontent.com/DavidWells-DB/Suspicious-User-Activity-Demo/master/Images/DetectionFramework5.png" />
# MAGIC
# MAGIC Machine Learning-Based Rules (Optimized): These are the most advanced types of rules, utilizing machine learning algorithms for threat detection. This could involve supervised learning (where the algorithm is trained on labeled examples of malicious and benign activity) or unsupervised learning (where the algorithm learns to detect anomalies without labeled examples). These rules require significant investment in data science and machine learning expertise.
# MAGIC
# MAGIC For Machine Learning, I am going to reference the DNS Analytics project <a href="https://www.databricks.com/solutions/accelerators/threat-detection">Detecting AgentTeslaRAT with Databricks</a> (Github <a href="https://github.com/databricks-industry-solutions/dns-analytics">here</a>) project that walks through the entire lifecycle of training and serving a Machine Learning model for cybersecurity use cases.
# MAGIC
# MAGIC <img src='https://www.databricks.com/wp-content/uploads/2020/10/blog-detecting-criminals-1.png'>
