# Databricks notebook source
# MAGIC %md This notebook sets up the companion cluster(s) to run the solution accelerator. It also creates the Workflow to illustrate the order of execution. Happy exploring! 
# MAGIC 🎉
# MAGIC
# MAGIC **Steps**
# MAGIC 1. Simply attach this notebook to a cluster and hit Run-All for this notebook. A multi-step job and the clusters used in the job will be created for you and hyperlinks are printed on the last block of the notebook. 
# MAGIC
# MAGIC 2. Run the accelerator notebooks: Feel free to explore the multi-step job page and **run the Workflow**, or **run the notebooks interactively** with the cluster to see how this solution accelerator executes. 
# MAGIC
# MAGIC     2a. **Run the Workflow**: Navigate to the Workflow link and hit the `Run Now` 💥. 
# MAGIC   
# MAGIC     2b. **Run the notebooks interactively**: Attach the notebook with the cluster(s) created and execute as described in the `job_json['tasks']` below.
# MAGIC
# MAGIC **Prerequisites** 
# MAGIC 1. You need to have cluster creation permissions in this workspace.
# MAGIC
# MAGIC 2. In case the environment has cluster-policies that interfere with automated deployment, you may need to manually create the cluster in accordance with the workspace cluster policy. The `job_json` definition below still provides valuable information about the configuration these series of notebooks should run with. 
# MAGIC
# MAGIC **Notes**
# MAGIC 1. The pipelines, workflows and clusters created in this script are not user-specific. Keep in mind that rerunning this script again after modification resets them for other users too.
# MAGIC
# MAGIC 2. If the job execution fails, please confirm that you have set up other environment dependencies as specified in the accelerator notebooks. Accelerators may require the user to set up additional cloud infra or secrets to manage credentials. 

# COMMAND ----------

# DBTITLE 1,Load Notebook Companion Library
# MAGIC %pip install -U git+https://github.com/databricks-academy/dbacademy@v1.0.14 git+https://github.com/databricks-industry-solutions/notebook-solution-companion@safe-print-html --quiet --disable-pip-version-check

# COMMAND ----------

dbutils.library.restartPython()

# COMMAND ----------

# DBTITLE 1,Load NotebookSolutionCompanion
from solacc.companion import NotebookSolutionCompanion

# COMMAND ----------

# DBTITLE 1,Suspicious User Activity: Job JSON config
job_json = {
    "name": "Investigate_Suspicious_User_Activity",
    "email_notifications": {
        "no_alert_for_skipped_runs": False
    },
    "webhook_notifications": {},
    "timeout_seconds": 0,
    "max_concurrent_runs": 1,
    "tasks": [
        {
            "task_key": "Generate_Data",
            "run_if": "ALL_SUCCESS",
            "notebook_task": {
                "notebook_path": f"/0.1 Data Creation",
                "source": "WORKSPACE"
            },
            "job_cluster_key": "Suspicious_User_Activity_Cluster",
            "timeout_seconds": 0,
            "email_notifications": {}
        },
        {
            "task_key": "Investigate_Suspicious_Sharepoint_Activity",
            "depends_on": [
                {
                    "task_key": "Generate_Data"
                }
            ],
            "run_if": "ALL_SUCCESS",
            "notebook_task": {
                "notebook_path": f"/1.1 [Detection] Investigate Suspicious Document Access Activity",
                "source": "WORKSPACE"
            },
            "job_cluster_key": "Suspicious_User_Activity_Cluster",
            "timeout_seconds": 0,
            "email_notifications": {}
        },
        {
            "task_key": "Suspicious_Number_Of_Emails_Sent_By_Employee",
            "depends_on": [
                {
                    "task_key": "Generate_Data"
                }
            ],
            "run_if": "ALL_SUCCESS",
            "notebook_task": {
                "notebook_path": f"1.2 [Detection] Suspicious Number of Emails Sent by Sender",
                "source": "WORKSPACE"
            },
            "job_cluster_key": "Suspicious_User_Activity_Cluster",
            "timeout_seconds": 0,
            "email_notifications": {}
        },
        {
            "task_key": "Investigate_Suspicious_User",
            "depends_on": [
                {
                    "task_key": "Investigate_Suspicious_Sharepoint_Activity"
                },
                {
                    "task_key": "Suspicious_Number_Of_Emails_Sent_By_Employee"
                }
            ],
            "run_if": "ALL_SUCCESS",
            "notebook_task": {
                "notebook_path": f"2.1 [Investigation] Investigate Suspicious User",
                "source": "WORKSPACE"
            },
            "job_cluster_key": "Suspicious_User_Activity_Cluster",
            "timeout_seconds": 0,
            "email_notifications": {}
        },
        {
            "task_key": "Disable_Suspicious_User",
            "depends_on": [
                {
                    "task_key": "Investigate_Suspicious_User"
                }
            ],
            "run_if": "ALL_SUCCESS",
            "notebook_task": {
                "notebook_path": f"3.1 [Response] Disable Suspicious User",
                "source": "WORKSPACE"
            },
            "job_cluster_key": "Suspicious_User_Activity_Cluster",
            "timeout_seconds": 0,
            "email_notifications": {}
        }
    ],
    "job_clusters": [
        {
            "job_cluster_key": "Suspicious_User_Activity_Cluster",
            "new_cluster": {
                "cluster_name": "",
                "spark_version": "13.3.x-scala2.12",
                "spark_conf": {
                    "spark.master": "local[*, 4]",
                    "spark.databricks.cluster.profile": "singleNode"
                },
                "node_type_id": {"AWS": "m4.large", "MSA": "Standard_DS3_v2", "GCP": "n1-highmem-4"}, # different from standard API
                "driver_node_type_id": "m4.large",
                "custom_tags": {
                    "ResourceClass": "SingleNode"
                },
                "enable_elastic_disk": True,
                "data_security_mode": "SINGLE_USER",
                "runtime_engine": "STANDARD",
                "num_workers": 0
            }
        }
    ],
    "tags": {
        "ID": "2024.01.10",
        "Team": "Cybersecurity"
    },
    "format": "MULTI_TASK"
}

# COMMAND ----------

dbutils.widgets.dropdown("run_job", "False", ["True", "False"])
run_job = dbutils.widgets.get("run_job") == "True"
NotebookSolutionCompanion().deploy_compute(job_json, run_job=run_job)
