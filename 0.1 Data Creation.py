# Databricks notebook source
# MAGIC %md
# MAGIC ### Data Creation Notebook
# MAGIC
# MAGIC This notebook generates the data required for the detection, investigation and response notebooks. It saves the generated events to `/tmp/detection_maturity` folder in DBFS.

# COMMAND ----------

# MAGIC %md 
# MAGIC ### Run helper methods and import required libraries

# COMMAND ----------

# DBTITLE 1,Import helper methods
# MAGIC %run "./0.0 Helper Methods"

# COMMAND ----------

# DBTITLE 1,Import required libraries
# MAGIC %pip install faker

# COMMAND ----------

# DBTITLE 1,Delete old demo data
# Delete the saved table folder
dbutils.fs.rm("/tmp/detection_maturity", True)
dbutils.fs.mkdirs("/tmp/detection_maturity")
dbutils.fs.mkdirs("/tmp/detection_maturity/tables/")

# COMMAND ----------

# MAGIC %md
# MAGIC # Demo Variables

# COMMAND ----------

# Notebook level variables

###########################
## CHANGE ME AS REQUIRED ##
###########################
debug = False
target_user = 'David Wells' # The target malicious user
target_user_email = 'david.wells@company.com' # The target malicious user's email
target_user_azure_guid = '78687760-202a-4666-a79e-7cef89b8a44d' # Set this to the Azure Entra GUID of the user to be disabled in '3.1 [Response] Disable Suspicious User'

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC ## Example 1: Pattern based detection
# MAGIC
# MAGIC Generate proxy URL filter logs with malicious logs embedded.

# COMMAND ----------

from faker import Faker
import random
from pyspark.sql import SparkSession
from datetime import datetime, timedelta
from pyspark.sql.functions import col, when

def generate_sample_logs(num_events: int = 10000, num_domains: int = 100, num_ips: int = 100, num_malware_domains: int = 10, seed: int = 42):
    """
    Generate a sample DataFrame of DNS query logs.

    Parameters:
    num_events (int, optional): The total number of events to generate. Defaults to 10000.
    num_domains (int, optional): The number of unique domains to generate. Defaults to 100.
    num_ips (int, optional): The number of unique IP addresses to generate. Defaults to 100.
    num_malware_domains (int, optional): The number of unique malware-related domains to include. Defaults to 10.
    seed (int, optional): The seed for the random number generator. Defaults to 42.

    Returns:
    pyspark.sql.DataFrame: A DataFrame of sample DNS query logs.
    """
    # Create a Faker instance
    fake = Faker()

    # Set the random seed
    Faker.seed(seed)
    random.seed(seed)

    # Prepare the random time variables
    # Define your start date as one day before now
    start_date = datetime.now() - timedelta(days=1)

    # Define your end date as the current time
    end_date = datetime.now()

    # Get the difference between the dates in seconds
    time_diff = int((end_date - start_date).total_seconds())

    # Define URL categories
    benign_url_categories = ["Business", "Social Media", "Shopping"]
    malicious_url_categories = ["Malware", "Adult/Mature", "Criminal Activity"]
    
    # Generate the logs
    logs = [(start_date + timedelta(seconds=random.randint(0, time_diff)), fake.ipv4(), fake.domain_name(), random.choice(malicious_url_categories) if random.randint(0, 9) == 1 else random.choice(benign_url_categories)) for _ in range(num_events)]

    logs.extend([(datetime.now() - timedelta(minutes= 5 * i), "10.25.50.33", random.choice(["young-flores.com", "wall-underwood.net", "31337.hk", "wa.ankabuttech.com", "psp-th.info"]), "Malware") for i in range(7*24*60//5)])
    logs.extend([(datetime.now() - timedelta(minutes= 5 * i), "10.33.2.5", random.choice(["young-flores.com", "wall-underwood.net", "31337.hk", "wa.ankabuttech.com", "psp-th.info"]), "Malware") for i in range(3*24*60//5)])

    # Convert the logs to a DataFrame
    df = spark.createDataFrame(logs, ["date", "ip_address", "domain", "url_category"])
    df = df.withColumn("outcome", when((col("url_category") == "Malware") | (col("url_category") == "Criminal Activity") | (col("url_category") == "Adult/Mature"),"Blocked").otherwise("Allowed"))
    df = sort_by_column(df, 'date')

    return df

# Generate the sample logs
df_logs = generate_sample_logs()

if debug:
    df_logs.display()
else:
    df_logs.write.format("delta").option("mergeSchema", "true").mode('overwrite').save('/tmp/detection_maturity/tables/url_filtering') 
    df_logs.display()


# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC ## Example 2: Threshold-based detection
# MAGIC
# MAGIC Generate web logs with one IP generating a high number of events.

# COMMAND ----------

from pyspark.sql import SparkSession
from pyspark.sql.functions import lit, col
from faker import Faker
import random
from datetime import datetime, timedelta

# Initialize the faker generator
fake = Faker()

# Define the start and end dates
start_date = datetime.now() - timedelta(days=7)
end_date = datetime.now()

# Get the difference between the dates in seconds
time_diff = int((end_date - start_date).total_seconds())

# Define the malicious IP
malicious_ip = fake.ipv4()

IPs = []
for _ in range(0, 800):
    IPs.append(fake.ipv4())

# List of pages/files in your website
pages = ['/page' + str(i) for i in range(1, 21)] + ['/file' + str(i) for i in range(1, 21)]

# HTTP methods
http_methods = ["GET", "POST", "PUT", "DELETE"]

# HTTP status codes
status_codes = [200, 201, 204, 400, 401, 403, 404, 500]

# Generate the logs
logs = []

for _ in range(10000):  # Adjust this number to generate more or fewer logs
    # Choose a random number of seconds within the range
    random_seconds = random.randint(0, time_diff)

    # Calculate the timestamp
    timestamp = start_date + timedelta(seconds=random_seconds)

    # Occasionally use the malicious IP
    if random.random() < 0.1:  # Adjust this number to change the frequency of the malicious IP
        ip = malicious_ip
    else:
        ip = random.choice(IPs)

    # Generate the user agent
    user_agent = fake.user_agent()

    # Generate the page request
    page = random.choice(pages)

    # Generate the HTTP method
    http_method = random.choice(http_methods)

    # Generate the status code
    status_code = random.choice(status_codes)

    # Add the log to the list
    logs.append((timestamp, ip, user_agent, page, http_method, status_code))

# Convert the logs to a DataFrame
df = spark.createDataFrame(logs, ["timestamp", "ip", "user_agent", "page", "http_method", "status_code"])
df = sort_by_column(df, 'timestamp' )


if debug:
    df.display()
else:
    df.write.format("delta").option("mergeSchema", "true").mode('overwrite').save('/tmp/detection_maturity/tables/web_logs')
    df.display()


# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC ## Example 3: Anomaly Detection
# MAGIC
# MAGIC Generate user logins with one user (defined by the `target_user` varaible above) generating a statistically significant number based on their own activities

# COMMAND ----------

from pyspark.sql import SparkSession
from pyspark.sql.functions import lit, col
from faker import Faker
from pyspark.sql import functions as F
import random
from datetime import datetime, timedelta

def generate_sample_statistically_significant_data():
    # List of sample users
    users = ['John Walker', 'Rick Burns', 'Joe Chew', 'Sarah Smith', 'John Doe', 'Jane Doe']

    # Generate a random number of events for each user for the past 12 days
    data = []
    for i in range(12):
        date = datetime.now() - timedelta(days=i)
        for user in users:
            for _ in range(random.randint(1, 3)):                
                if user == 'John Walker' and i < 1:  # Note: This example doesn't use the target_user variable
                    for _ in range(random.randint(5, 15)):
                        outcome = 'Failure' if random.randint(1, 10) == 1 else 'Success'
                        data.append((date, user, 'Login Attempt', outcome))
                elif user == 'Rick Burns' and i < 1:
                    for _ in range(0, 5):
                        outcome = 'Failure' if random.randint(1, 10) == 1 else 'Success'
                        data.append((date, user, 'Login Attempt', outcome))
                else:
                    outcome = 'Failure' if random.randint(1, 10) == 1 else 'Success'
                    data.append((date, user, 'Login Attempt', outcome))

    # Convert the data to a pandas DataFrame
    df = spark.createDataFrame(data, ['date', 'user_id', 'action', 'outcome'])
    df = sort_by_column(df, 'date')

    #Return the dummy values
    return df

df = generate_sample_statistically_significant_data()

if debug:
    df.display()
else:
    # Write delta table to temp directory
    df.write.format("delta").option("mergeSchema", "true").mode('overwrite').save('/tmp/detection_maturity/tables/customer_logins')
    df.display()

# COMMAND ----------

# MAGIC %md 
# MAGIC ## Example #4: Trend-based anomaly detection

# COMMAND ----------

import random
from datetime import datetime, timedelta
from pyspark.sql import functions as F

def random_datetime_days_ago(i):
    """
    Generates a random datetime within the day i days ago.

    Parameters:
    i (int): The number of days ago.

    Returns:
    datetime: The randomly generated datetime.
    """
    if i == 0:
        # Calculate the start of the current day
        start_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        # The end date is the current datetime
        end_date = datetime.now()
    else:
        # Calculate the start and end of the day i days ago
        start_date = datetime.now() - timedelta(days=i+1)
        end_date = datetime.now() - timedelta(days=i)

    # Get the difference between the start and end in seconds
    time_diff = int((end_date - start_date).total_seconds())

    # Choose a random number of seconds within the range
    random_seconds = random.randint(0, time_diff)

    # Calculate the random datetime
    random_datetime = start_date + timedelta(seconds=random_seconds)

    return random_datetime

def generate_random_filename():
    """
    Generates a random filename with a plausible business name and a random file extension.

    Returns:
    str: The generated filename.
    """
    # List of possible file extensions
    extensions = ['.docx', '.xlsx', '.pdf', '.jpg', '.png']

    # Generate a plausible business-related word
    filename = fake.bs().replace(' ', '_')

    # Choose a random file extension
    extension = random.choice(extensions)

    return filename + extension

def generate_sample_statistically_significant_trending_data():
    # List of sample users
    users = [target_user, 'Rick Burns', 'Joe Chew', 'Sarah Smith', 'John Doe', 'Jane Doe']

    # Generate a random number of events for each user for the past 12 days
    data = []
    for i in range(15):
        for user in users:
                if user == target_user:
                    if i < 1:  # target_user generates more events in the last day
                        for _ in range(random.randint(25, 35)):
                            data.append((random_datetime_days_ago(i), user, 'Document Accessed', generate_random_filename(), random.randint(1, 5)))
                    else:
                        for _ in range(random.randint(1, 2)):
                            data.append((random_datetime_days_ago(i), user, 'Document Accessed', generate_random_filename(), random.randint(1, 5)))
                elif user == 'Rick Burns':
                    if i < 1:
                        for _ in range(15, 20):
                            data.append((random_datetime_days_ago(i), user, 'Document Accessed', generate_random_filename(), random.randint(1, 5)))
                    else:
                        for _ in range(15, 20):
                            data.append((random_datetime_days_ago(i), user, 'Document Accessed', generate_random_filename(), random.randint(1, 5)))
                else:
                    for _ in range(0, random.randint(0, 2)):
                        data.append((random_datetime_days_ago(i), user, 'Document Accessed', generate_random_filename(), random.randint(1, 5)))

    # Create the dataframe
    df = spark.createDataFrame(data, ['date', 'user_id', 'action', 'document_name', 'no_prints'])
    df = sort_by_column(df, 'date')

    #Return the values
    return df

df = generate_sample_statistically_significant_trending_data()

if debug:
    df.display()
else:
    # Write delta table to temp directory
    df.write.format("delta").option("mergeSchema", "true").mode('overwrite').save('/tmp/detection_maturity/tables/sharepoint')
    df.display()

# COMMAND ----------

# MAGIC %md
# MAGIC # Investigation Events

# COMMAND ----------

# MAGIC %md
# MAGIC ### User Logins

# COMMAND ----------

from pyspark.sql import SparkSession
from pyspark.sql.functions import lit, col
from pyspark.sql import functions as F
import random
from datetime import datetime, timedelta

def generate_user_login_data():
    # List of sample users
    users = [target_user, 'Rick Burns', 'Joe Chew', 'Sarah Smith', 'John Doe', 'Jane Doe']

    # Generate a random number of events for each user for the past 12 days
    david_hostnames = [["bfsk021-MacM12022-laptop", "10.25.50.33"],  ["web-EAST1-84.databricks.com", "10.33.2.5"]]
    data = []
    for i in range(12):
        date = datetime.now() - timedelta(days=i)
        for user in users:               
            if user == target_user:  # target_usertarget_user generates more events in the last day
                for _ in range(random.randint(1, 7)):
                    outcome = 'Failure' if random.randint(1, 10) == 1 else 'Success'
                    malicious_host = david_hostnames[0] if random.random() < .9 else david_hostnames[1]
                    host, ip = malicious_host[0], malicious_host[1]
                    data.append((date, user, 'Login Attempt', host, ip , outcome))
            elif user == 'Rick Burns':
                for _ in range(0, 3):
                    outcome = 'Failure' if random.randint(1, 10) == 1 else 'Success'
                    data.append((date, user, 'Login Attempt', fake.hostname(), fake.ipv4_private(), outcome))
            else:
                outcome = 'Failure' if random.randint(1, 10) == 1 else 'Success'
                data.append((date, user, 'Login Attempt', fake.hostname(),fake.ipv4_private(), outcome))

    # Convert the data to a pandas DataFrame
    df = spark.createDataFrame(data, ['date', 'user_id', 'action', 'dest_hostname', "src_ip", 'outcome'])
    df = sort_by_column(df, 'date')

    # Return the dummy values
    return df

df = generate_user_login_data()

if debug:
    df.display()
else:
    # Write table to temporary directory
    df.write.format("delta").format("delta").option("mergeSchema", "true").mode('overwrite').save('/tmp/detection_maturity/tables/user_logins')
    df.display()

# COMMAND ----------

# MAGIC %md
# MAGIC # User Department

# COMMAND ----------

# DBTITLE 1,Generate Workday Data for the Malicious User
data = [[target_user, 'Accounting', 'Manager']]
df = spark.createDataFrame(data, ['employee', 'department', 'title'])

if debug:
    df.display()
else:
    # Write table to temporary directory  
    df.write.format("delta").format("delta").option("mergeSchema", "true").mode('overwrite').save('/tmp/detection_maturity/tables/workday')
    df.display()

# COMMAND ----------

from pyspark.sql import SparkSession
from pyspark.sql.functions import udf
from pyspark.sql.types import StringType, IntegerType, TimestampType
import random
from datetime import datetime, timedelta

# Define a function to generate a random datetime within the last 7 days
def random_datetime_last_7_days():
    end_date = datetime.now()
    start_date = end_date - timedelta(days=7)
    time_diff = (end_date - start_date).total_seconds()
    random_seconds = random.randint(0, time_diff)
    return start_date + timedelta(seconds=random_seconds)

# Define DLP event types
dlp_events = [
    ("Attempting to email document with 'Secret' classification.", "High"),
    ("Attempting to save document labeled 'Internal' to external file share.", "Medium"),
    ("Attempting to upload 'Confidential' document to cloud storage.", "Medium"),
    ("Attempting to Email 'Confidential' document to unauthorized recipient.", "Low"),
    ("Attempting to download 'Secret' document to local machine.", "High"),
]

unblocked_high_for_bad_user = False

# Define a function to generate a random DLP event log
def generate_dlp_event(user, isBadUser=False):
    global unblocked_high_for_bad_user
    event, risk = random.choice(dlp_events)
    action = "Blocked" if ((risk == "High" and random.random() < 0.9) or (risk == "Medium" and random.random() < 0.5)) else "Allowed"

    # Have one high risk unblocked
    if isBadUser and not unblocked_high_for_bad_user:
        action="Allowed"
        risk = "High"
        event = "Attempting to zip file with 'Confidential' document."
        unblocked_high_for_bad_user = True
    
    return (random_datetime_last_7_days(), user, generate_random_filename() if random.random() < 0.5 else fake.file_name(), event, risk, action)

def generate_dlp_events():
    users = [fake.name() for _ in range(250)]

    # Generate DLP event logs for random users
    event_logs = [generate_dlp_event(random.choice(users)) for _ in range(1000)]

    # Generate additional suspicious events for `target_user`
    event_logs.extend([generate_dlp_event(target_user, True) for _ in range(25)])

    # Define the schema for the DataFrame
    schema = ['timestamp', 'user', 'filename', 'event', 'risk', 'action']

    # Create DataFrame
    df = spark.createDataFrame(event_logs, schema)
    return df

df = generate_dlp_events()

if debug:
    df.display()
else:
    # Write table to temporary directory
    df.write.format("delta").option("mergeSchema", "true").mode('overwrite').save('/tmp/detection_maturity/tables/dlp')
    df.display()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Antivirus Logs

# COMMAND ----------

from random import choice, randint
from datetime import datetime, timedelta

event_types = [
    "MALWAREPROTECTION_SCAN_STARTED",
    "MALWAREPROTECTION_SCAN_COMPLETED",
    "MALWAREPROTECTION_SCAN_CANCELLED",
    "MALWAREPROTECTION_SCAN_PAUSED",
    "MALWAREPROTECTION_SCAN_RESUMED",
    "MALWAREPROTECTION_SCAN_FAILED",
    "MALWAREPROTECTION_MALWARE_DETECTED",
    "MALWAREPROTECTION_MALWARE_ACTION_TAKEN",
    "MALWAREPROTECTION_MALWARE_ACTION_FAILED",
    "MALWAREPROTECTION_QUARANTINE_RESTORE"
]

actions = [
    "Clean",
    "Quarantine",
    "Remove",
    "Allow",
    "User defined",
    "No action",
    "Block"
]

def generate_antivirus_logs(days=12, hosts=10):
    david_hostnames = ["bfsk021-MacM12022-laptop", "web-EAST1-84.databricks.com"]
    logs = []
    now = datetime.now()
    for i in range(days):
        day = now - timedelta(days=i)

        # Manually create an entry for David's laptop
        host = 'bfsk021-MacM12022-laptop'
        event_type = "MALWAREPROTECTION_MALWARE_DETECTED"
        action = "Remove"
        time = day.replace(hour=9, minute=randint(0, 30))
        log = {
                "hostname": host,
                "event_type": event_type,
                "action": action,
                "time": time
            }
        logs.append(log)

        event_type = "MALWAREPROTECTION_MALWARE_ACTION_TAKEN"
        action = "Remove"
        time = time + timedelta(minutes=random.randint(2, 5), seconds=random.randint(0, 59))
        log = {
                "hostname": host,
                "event_type": event_type,
                "action": action,
                "time": time
            }
        logs.append(log)        

        # Create entries for the infected web host
        if i < 3:
            host = 'web-EAST1-84.databricks.com'
            event_type = choice(event_types)
            action = choice(actions)
            time = day.replace(hour=randint(0, 23), minute=randint(0, 59))
            log = {
                "hostname": host,
                "event_type": event_type,
                "action": action,
                "time": time
            }
            logs.append(log)

            event_type = "MALWAREPROTECTION_MALWARE_ACTION_TAKEN"
            action = "Remove"
            time = time + timedelta(minutes=random.randint(2, 5), seconds=random.randint(0, 59))
            log = {
                    "hostname": host,
                    "event_type": event_type,
                    "action": action,
                    "time": time
                }
            logs.append(log)   

        for j in range(hosts):
            host = fake.hostname()
            event_type = choice(event_types)
            action = choice(actions)
            time = day.replace(hour=randint(0, 23), minute=randint(0, 59))

            log = {
                "hostname": host,
                "event_type": event_type,
                "action": action,
                "time": time
            }
            logs.append(log)
    # Create DataFrame
    df = spark.createDataFrame(logs)
    return df

df = generate_antivirus_logs()

if debug:
    df.display()
else:
    # Write delta table to temporary folder
    df.write.format("delta").option("mergeSchema", "true").mode('overwrite').save('/tmp/detection_maturity/tables/antivirus')
    df.display()

# COMMAND ----------

# MAGIC %md
# MAGIC ## Email Logs

# COMMAND ----------

from pyspark.sql import SparkSession
from pyspark.sql.functions import col
from pyspark.sql.types import *
import random
from datetime import datetime, timedelta

def generate_email_logs(num_logs=5000):
    spark = SparkSession.builder.appName("email_logs").getOrCreate()

    # Define schema for the DataFrame
    schema = StructType(
        [
            StructField("date", TimestampType(), True),
            StructField("sender", StringType(), True),
            StructField("recipient", StringType(), True),
            StructField("subject", StringType(), True),
            StructField("message_body", StringType(), True),
            StructField("signature", StringType(), True),
            StructField("priority", StringType(), True),
            StructField("read_receipt", BooleanType(), True),
            StructField("format", StringType(), True),
            StructField("thread_id", StringType(), True),
            StructField("spam_score", DoubleType(), True),
            StructField("status_flags", StringType(), True),
        ]
    )
    senders = [fake.email() for _ in range(0, 50)]

    # Generate fake data
    data = [
        (
            datetime.now()
            - timedelta(
                days=random.randint(0, 30),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59),
            ),
            random.choice(senders),
            fake.email(),
            fake.sentence(),
            fake.text(),
            fake.sentence(),
            fake.random_element(["High", "Medium", "Low"]),
            fake.boolean(),
            fake.random_element(["plain", "HTML"]),
            fake.uuid4(),
            fake.random_number(digits=2, fix_len=True) / 100,
            fake.random_element(["read", "replied", "forwarded", "unread"]),
        )
        for _ in range(num_logs)
    ]

    for i in range(2, 30):
        for _ in range(0, random.randint(0, 2)):
            data.append(
                (
                    datetime.now()
                    - timedelta(
                        days=i,
                        hours=random.randint(0, 23),
                        minutes=random.randint(0, 59),
                        seconds=random.randint(0, 59),
                    ),
                    target_user_email,
                    fake.email(),
                    fake.sentence(),
                    fake.text(),
                    fake.sentence(),
                    fake.random_element(["High", "Medium", "Low"]),
                    fake.boolean(),
                    fake.random_element(["plain", "HTML"]),
                    fake.uuid4(),
                    fake.random_number(digits=2, fix_len=True) / 100,
                    fake.random_element(["read", "replied", "forwarded", "unread"]),
                )
            )

    for _ in range(0, 500):
        data.append(
            (
                datetime.now()
                - timedelta(
                    hours=random.randint(0, 2),
                    minutes=random.randint(0, 59),
                    seconds=random.randint(0, 59),
                ),
                target_user_email,
                fake.email(),
                fake.sentence(),
                fake.text(),
                fake.sentence(),
                fake.random_element(["High", "Medium", "Low"]),
                fake.boolean(),
                fake.random_element(["plain", "HTML"]),
                fake.uuid4(),
                fake.random_number(digits=2, fix_len=True) / 100,
                fake.random_element(["read", "replied", "forwarded", "unread"]),
            )
        )

    # Create DataFrame
    df = spark.createDataFrame(data, schema)

    # Sort DataFrame by date_and_time
    df = df.orderBy(col("date").desc())

    return df

# Generate 2000 fake email logs
df = generate_email_logs()

if debug:
    df.display()
else:
    # Save DataFrame into a table
    df.write.format("delta").option("mergeSchema", "true").mode("overwrite").save("/tmp/detection_maturity/tables/email")
    df.display()

# COMMAND ----------

from pyspark.sql import SparkSession
from datetime import datetime, timedelta
import random

def generate_fake_ciam_logs_with_anomaly(num_logs, num_days_history=30):
    """
    Generate a PySpark DataFrame of fake CIAM event logs with one user ('David Wells') 
    having anomalously high events in the last hour compared to the historical average. 
    """    
    # Possible outcomes for a login attempt
    all_outcomes = ['BLOCKED', 'DENIED', 'SUCCESS']
    bad_outcomes = ['BLOCKED', 'DENIED']
    users = [fake.name() for _ in range(15)]
    
    # List to store the generated logs
    logs = []
    
    # Generate historical data for other users
    for day in range(num_days_history):
        for _ in range(num_logs):
            login_id = random.choice(users)
            _event_date = datetime.now() - timedelta(days=day, hours=random.randint(1, 24))
            outcome = random.choices(all_outcomes, weights=[28, 2, 70])[0]
            logs.append((login_id, _event_date, outcome))
            
    # Generate consistent and low failed attempts for target_user in the historical data
    for day in range(2, num_days_history):
        for _ in range(3):  # Small number of failed attempts to set a low baseline
            _event_date = datetime.now() - timedelta(days=day, hours=random.randint(1, 24))
            outcome = random.choice(bad_outcomes)
            logs.append((target_user, _event_date, outcome))
    
    # Generate a large number of failed attempts for target_user in the last hour
    num_anomalous_logs = 713  # Large number of failed attempts in the last hour
    for _ in range(num_anomalous_logs):
        _event_date = datetime.now() - timedelta(minutes=random.randint(0, 30))
        outcome = random.choices(bad_outcomes, weights=[80, 20])[0]
        logs.append((target_user, _event_date, outcome))
    
    # Define the schema for the PySpark DataFrame
    schema = ["login_id", "_event_date", "outcome"]
    
    # Create a PySpark DataFrame from the list of logs
    logs_df = spark.createDataFrame(logs, schema=schema)
    
    return logs_df

# Generate a sample of fake CIAM event logs having anomalously high events
num_days = 50
df = generate_fake_ciam_logs_with_anomaly(num_days)

if debug:
    df.show()
else:
    # Save the logs to the specified path as a Delta table
    df.write.format("delta").mode('overwrite').save('/tmp/detection_maturity/tables/ciam')

    # Show the first few rows of the generated logs (optional)
    df.display()

# COMMAND ----------

# MAGIC %md
# MAGIC # Alert, Investigate and Response Tables

# COMMAND ----------

from pyspark.sql import Row
from datetime import datetime
from pyspark.sql.types import StructType, StructField, LongType, StringType, MapType, TimestampType

# Define the schema
schema = StructType([
    StructField("ID", LongType(), True),
    StructField("date", TimestampType(), True),
    StructField("alert_name", StringType(), True),
    StructField("alert_desc", StringType(), True),
    StructField("alert_status", StringType(), True),
    StructField("alert_source", StringType(), True),
    StructField("alert_category", StringType(), True),
    StructField("alert_subcategory", StringType(), True),
    StructField("tags", StringType(), True),
    StructField("entity_id", StringType(), True),
    StructField("entity_type", StringType(), True),
    StructField("alert_details", MapType(StringType(), StringType()), True)
])

def create_alerts():
    # Define some possible values for the alert fields
    alert_names = ["Failed Login", "Data Exfiltration", "Unusual Access", "Privilege Escalation", "Large Data Transfer"]
    alert_statuses = ["Open", "Closed", "In Progress"]
    alert_sources = ["System", "Network", "User"]
    alert_categories = ["Authentication", "Data", "Access", "Privilege", "Transfer"]
    alert_subcategories = ["Login", "Exfiltration", "Location", "Admin Group", "Size"]
    entity_types = ["User", "System", "Network"]

    # Example data
    data = [
        Row(ID=34221, date=datetime.now(), alert_name="Failed Login", alert_desc="Multiple failed login attempts", 
            alert_status="Open", alert_source="System", alert_category="Authentication", alert_subcategory="Login", 
            tags="critical", entity_id="User1", entity_type="User", 
            alert_details={"IP": "192.168.1.1", "Attempts": "5"}),
        
        Row(ID=34222, date=datetime.now(), alert_name="Data Exfiltration", alert_desc="Large amount of data transferred", 
            alert_status="Open", alert_source="Network", alert_category="Data", alert_subcategory="Exfiltration", 
            tags="high", entity_id="User2", entity_type="User", 
            alert_details={"IP": "192.168.1.2", "DataSize": "1GB"})
    ]

    # Generate 15 more samples
    for i in range(3, 18):
        alert_name = random.choice(alert_names)
        alert_status = random.choice(alert_statuses)
        alert_source = random.choice(alert_sources)
        alert_category = random.choice(alert_categories)
        alert_subcategory = random.choice(alert_subcategories)
        entity_type = random.choice(entity_types)
        
        # Generate a random user and IP address
        user = fake.user_name()
        ip = fake.ipv4()
        
        # Generate a random date within the last 30 days
        date = datetime.now() - timedelta(days=random.randint(0, 30))
        
        # Create the alert details dictionary
        alert_details = {"IP": ip, "Details": f"{alert_name} detected from {ip}"}
        
        # Create the row
        row = Row(ID=i+34221, date=date, alert_name=alert_name, alert_desc=f"{alert_name} detected", 
                alert_status=alert_status, alert_source=alert_source, alert_category=alert_category, 
                alert_subcategory=alert_subcategory, tags="tag", entity_id=user, entity_type=entity_type, 
                alert_details=alert_details)
        
        # Append the row to the data list
        data.append(row)

    # Create a DataFrame from the data
    df = spark.createDataFrame(data, schema)

    return df

df = create_alerts()

if debug:
    df.display()
else:
    # Save the DataFrame as a table in the 'demo' database
    df.write.format("delta").mode('overwrite').save('/tmp/detection_maturity/tables/alert')
    df.display()

# COMMAND ----------

df = spark.table('david_wells.demo.alert')
df.display()

# COMMAND ----------

from pyspark.sql.types import StructType, StructField, LongType, StringType, MapType, TimestampType
from pyspark.sql.functions import monotonically_increasing_id
from faker import Faker
import random
from datetime import datetime, timedelta

# Initialize the Faker generator
fake = Faker()

# Define the schema
schema = StructType([
    StructField("id", LongType(), True),
    StructField("date", TimestampType(), True),
    StructField("investigation_name", StringType(), True),
    StructField("status", StringType(), True),
    StructField("status_message", StringType(), True),
    StructField("data", MapType(StringType(), StringType()), True)
])

# Define some possible values for the investigation fields
investigation_names = ["Unauthorized Access", "Data Exfiltration", "Malware Infection", "Privilege Escalation", "Phishing Attempt"]
statuses = ["new", "in progress", "failed", "complete"]
status_messages = ["Investigation started", "Investigation in progress", "Investigation failed", "Investigation complete"]
entity_types = ["username", "ip", "email"]

data = []

def create_investigation_entry(islastfiveminutes=False):
    investigation_name = random.choice(investigation_names)
    status = random.choice(statuses)
    status_message = random.choice(status_messages)
    entity_type = random.choice(entity_types)
    
    # Generate a random user, IP address, and email
    user = fake.user_name()
    ip = fake.ipv4()
    email = fake.email()
    
    # Generate a random date within the last 30 days
    timediff = timedelta(minutes=random.randint(0, 4), seconds=random.randint(0, 59)) if islastfiveminutes else timedelta(minutes=random.randint(0, 3000), seconds=random.randint(0, 59))
    date = datetime.now() - timediff
    
    # Based on the time, adjust the status and status_message
    if date < datetime.now() - timedelta(minutes=5):  # More than 5 minutes ago
        status = "complete" if random.random() < 0.99 else "failed"
        status_message = "Investigation complete"
    else:
        status = random.choice(["new", "in progress"])
        status_message = "Investigation in progress"
    
    # Create the data dictionary
    data_dict = {"entity": user if entity_type == "username" else ip if entity_type == "ip" else email, "entity_type": entity_type}
    
    # Create the row
    row = Row(id=i, date=date, investigation_name=investigation_name, status=status, status_message=status_message, data=data_dict)
    
    # Append the row to the data list
    data.append(row)

for i in range(1, 501):
    create_investigation_entry(False)

for i in range(0, 5):
    create_investigation_entry(True)

# Create a DataFrame from the data
df = spark.createDataFrame(data, schema)
df = df.sort(df.date)

#Doing this because I updated the method to sort by date and then realized I need to order the IDs
df = df.withColumn("id", monotonically_increasing_id() + 5021)

if debug:
    df.display()
else:
    # Save the DataFrame as a table in the 'demo' database
    df.write.format("delta").mode('overwrite').save('/tmp/detection_maturity/tables/investigation')
    df.display()

# COMMAND ----------

# MAGIC %fs ls /tmp/detection_maturity/tables
# MAGIC

# COMMAND ----------

from pyspark.sql import SparkSession
from pyspark.sql.types import LongType, StringType, StructField, StructType

# Define the schema corresponding to the SQL table definition
schema = StructType([
    StructField("ID", LongType(), True),
    StructField("UserName", StringType(), True),
    StructField("UserEmail", StringType(), True),
    StructField("TriggerEvent", StringType(), True),
    StructField("ResponseAction", StringType(), True),
])

# Use the schema to create a DataFrame
data = [
    (1, 'JohnDoe', 'johndoe@example.com', 'Multiple Failed Login Attempts', 'Disable User'),
    (2, 'JaneSmith', 'janesmith@example.com', 'Data Exfiltration Attempt', 'Disable User'),
    (3, 'BobJohnson', 'bobjohnson@example.com', 'Unusual Access Pattern', 'Disable User'),
    (4, 'AliceWilliams', 'alicewilliams@example.com', 'Privilege Escalation', 'Disable User'),
    (5, 'CharlieBrown', 'charliebrown@example.com', 'Large Data Transfer', 'Disable User')
]

# Create the dataframe
df = spark.createDataFrame(data, schema)

# Write the data to the Delta location
df.write.format("delta").mode("overwrite").save("/tmp/detection_maturity/tables/response_table")

# COMMAND ----------

from pyspark.sql import SparkSession
from pyspark.sql import Row

# Create a DataFrame for the new row to be inserted
new_user_row = [Row(Username=target_user, ID=target_user_azure_guid)]
new_users_df = spark.createDataFrame(new_user_row)

# Append the new row to the existing Delta files at the specified path
new_users_df.write.format("delta").mode("append").save("/tmp/detection_maturity/tables/users")
