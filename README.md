# Suspicious-User-Activity-Demo
This is a Databricks Cybersecurity demo for building linked detection, investigation and response jobs in Databricks Workflows.

## Overview
The Suspicious-User-Activity-Demo is designed to show how to use Databricks to detect, investigate, and response to a cybersecurity threat. In this demo, we focus on two concepts:
- Using pre-built functions in Databricks to perform increasingly complex detection methods \(see the [helper methods](https://github.com/DavidWells-DB/Suspicious-User-Activity-Demo/blob/main/0.0%20Helper%20Methods.py) Notebook for more details\)
- Show how to create a Detection -> Investigation -> Response workflow that can pass information across Notebooks.

## Setup and Requirements
To run this demo, you'll need:
- A Databricks workspace
- Permission to write to `dbfs:/tmp/detection_maturity`
- Basic knowledge of Apache Spark
- An Azure Entra user ID and Graph API token

## Installation and Usage
To use this repo:
1. Clone the repository to your Databricks workspace.
1. Customize the variables at the top of [0.1 Data Creation](https://github.com/DavidWells-DB/Suspicious-User-Activity-Demo/blob/main/0.1%20Data%20Creation.py) and [3.1 \[Response\] Disable Suspicious User](https://github.com/DavidWells-DB/Suspicious-User-Activity-Demo/blob/main/3.1%20%5BResponse%5D%20Disable%20Suspicious%20User.py) as required
1. `[Optional]` Set up the Azure Developer environment
   1. Set up an Azure developer environment following [these instructions](https://azure.microsoft.com/en-ca/products/deployment-environments)
   1. Set up an Azure ID to access the [Graph API](https://learn.microsoft.com/en-us/graph/security-authorization)
   1. Create a Databricks Secret Scope and set three keys:
       - Azure Tenant ID
       - Azure Client ID
       - Azure Client Secret
    - Note: If you don't have an Azure Entra ID or Graph API token, disable the `3.1 [Response] Disable Suspicious User` Notebook.

Once complete, you can use this repo in three ways:
1. Run the `RUNME` notebook to create the Detection -> Investigation -> Response workflow job and cluster. 
   1. This will create a Workflows job that has four interconnected notebooks that pass data across the lifecycle. 
   1. Leading to an Azure Entra account being disabled
1. Open and run the `1.0 Evolving Use Cases` notebook, which showcases executing each Detection helper function against randomly generated events
1. Manually run the Detection, Investigation and Response notebooks
   - Note: Manually run the [0.1 Data Creation](https://github.com/DavidWells-DB/Suspicious-User-Activity-Demo/blob/main/0.1%20Data%20Creation.py) and [3.1 \[Response\] Disable Suspicious User](https://github.com/DavidWells-DB/Suspicious-User-Activity-Demo/blob/main/3.1%20%5BResponse%5D%20Disable%20Suspicious%20User.py) notebook first.

## Helper Methods
The `0.0 Helper Methods` Notebook contains example functions that you can use in your environment to perform simple detections. The helper functions include:

### Get Helper Methods
Get Helper Methods support getting data from Databricks Delta tables. The methods include:

| Method | Description |
| ------ | ----------- |
| get_table | Retrieves a specific table from the Spark session based on the provided table name. |
| sort_by_column | Sorts a DataFrame based on a specified column in either ascending or descending order. |
| sort_by_columns | Sorts a DataFrame based on one or more specified columns in either ascending or descending order. |
| select_columns | Selects specific columns from a DataFrame. |
| aggregate_data | This function performs specified aggregations on a PySpark DataFrame and returns the result. |
| join_tables | Joins two DataFrames based on a specified join column. |

### Filter Helper Methods
Filter Helper Methods support filtering DataFrames for data specific to your use case. The methods include:

| Method | Description |
| ------ | ----------- |
| filter_column_by_value | Filters a DataFrame based on a value in a specific column. |
| filter_columns_by_values | Filters a DataFrame based on a value in specific columns. |
| filter_column_by_category | Filters a DataFrame based on a category in a specific column. |
| filter_columns_by_categories | Filters a DataFrame based on a category in specific columns. |
| filter_column_by_date_range | Filters a DataFrame based on a date range in a specific column. |
| filter_columns_by_date_ranges | Filters a DataFrame based on a date range in specific columns. |
| filter_by_time | Filters a DataFrame based on a specified time range. |
| filter_by_relative_time | Filters a DataFrame based on a specified time range relative to the current time. |
| filter_rows_with_any_null | Filters a DataFrame to include rows where any of the specified columns have a null value. |
| filter_rows_with_all_null | Filters a DataFrame to include rows where all of the specified columns have a null value. |
| filter_column_by_string_pattern | Filters a DataFrame based on a string pattern in a specific column. |
| filter_columns_by_string_pattern | Filters a DataFrame based on a string pattern in specific columns. |
| filter_column_by_multiple_conditions | Filters a DataFrame based on multiple conditions. |
| filter_columns_by_multiple_conditions | Filters a DataFrame based on multiple conditions. |
| filter_column_by_custom_function | Filters a DataFrame based on a custom function applied to a specific column. |
| filter_columns_by_custom_function | Filters a DataFrame based on a custom function applied to specific columns. |

### Detection Helper Methods
Detection Helper Methods support executing detection logic on DataFrames relevant to your use case. The methods include:

| Method | Description |
| ------ | ----------- |
| pattern_based_rule | Filters a DataFrame based on a pattern in a specific column. |
| threshold_based_rule | Groups a DataFrame by a column and filters based on a count threshold. |
| threshold_based_rule_multiple_group_by | Groups a DataFrame by multiple columns and filters based on a count threshold. |
| statistical_anomaly_detection | Detects statistical anomalies in a DataFrame based on a z-score threshold. |
| statistical_anomaly_detection_group_by | Detects statistical anomalies in a DataFrame based on a z-score threshold. |
| trending_based_rule | Detects trends in a DataFrame based on a ratio threshold and time ranges. |
| statistically_significant_window_by_std | This function identifies the records in the input dataframe where the count of events in the last window of time is statistically significantly higher than the mean count of events in previous windows. |


## Contributing
If you'd like to contribute to the project, please follow these steps:
1. Fork the repository.
1. Create a new branch.
1. Make your changes and test them.
1. Push your changes to your fork.
1. Submit a pull request with a description of your changes.
