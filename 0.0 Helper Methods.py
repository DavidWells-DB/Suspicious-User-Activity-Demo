# Databricks notebook source
from pyspark.sql import SparkSession
from pyspark.sql.functions import col
from datetime import datetime, timedelta

def get_table(table_name):
    """
    Retrieves a specific table from the Spark session based on the provided table name.

    Args:
        table_name (str): The name of the table to retrieve.

    Returns:
        DataFrame: The DataFrame representing the specified table.

    Examples:
        df = get_table(spark, 'table_name')
    """
    return spark.table(table_name)


def sort_by_column(df, column_name, ascending=True):
    """
    Sorts a DataFrame based on a specified column in either ascending or descending order.

    Args:
        df (DataFrame): The input DataFrame to sort.
        column_name (str): The name of the column to sort by.
        ascending (bool, optional): Specifies the sorting order. Defaults to True (ascending order).

    Returns:
        DataFrame: The sorted DataFrame.

    Examples:
        sorted_df = sort_by_column(df, 'column_name', ascending=False)
    """
    return df.orderBy(col(column_name).asc() if ascending else col(column_name).desc())


def select_columns(df, *columns):
    """
    Selects specific columns from a DataFrame.

    Args:
        df (DataFrame): The input DataFrame.
        *columns (str): Variable number of column names to select.

    Returns:
        DataFrame: The DataFrame with only the selected columns.

    Examples:
        selected_df = select_columns(df, 'column1', 'column2')
    """
    return df.select(*columns)

def aggregate_data(df, group_by_columns, aggregation_columns, aggregation_functions, alias_names):
    """
    This function performs specified aggregations on a PySpark DataFrame and returns the result.
    
    Parameters:
    df (DataFrame): The input dataframe.
    group_by_columns (list): A list of column names to group by.
    aggregation_columns (list): A list of column names to perform aggregations on.
    aggregation_functions (list): A list of PySpark SQL functions to use for aggregations.
    alias_names (list): A list of alias names for the aggregated columns.
    
    Returns:
    DataFrame: A new DataFrame with the aggregated data.
    
    Example:
    Suppose we have a DataFrame 'df' with columns "user_id", "time", and "value", and we want to find the minimum and maximum time for each user_id.
    
    >>> df = aggregate_data(df=df, 
                             group_by_columns=["user_id"], 
                             aggregation_columns=["time", "time"], 
                             aggregation_functions=[F.min, F.max],
                             alias_names=["min_time", "max_time"])
                             
    This will return a DataFrame with columns "user_id", "min_time", and "max_time", where "min_time" and "max_time" are the minimum and maximum time for each user_id, respectively.
    """
    return df.groupBy(*group_by_columns).agg(*[fn(col_name).alias(alias_name)
                                               for col_name, fn, alias_name in zip(aggregation_columns,
                                                                                    aggregation_functions,
                                                                                    alias_names)])

def join_tables(df1, df2, join_column):
    """
    Joins two DataFrames based on a specified join column.

    Args:
        df1 (DataFrame): The first DataFrame.
        df2 (DataFrame): The second DataFrame.
        join_column (str): The column to perform the join operation on.

    Returns:
        DataFrame: The joined DataFrame.

    Examples:
        joined_df = join_tables(df1, df2, 'join_col')
    """
    return df1.join(df2, on=join_column)


# COMMAND ----------

from pyspark.sql import functions as F
from datetime import datetime, timedelta
from pyspark.sql.functions import col, lit

# 1a. Filter by Value
def filter_column_by_value(df, column, value):
    """
    Filters a DataFrame based on a value in a specific column.

    Parameters:
    df (pyspark.sql.DataFrame): The DataFrame to filter.
    column (str): The column name to filter on.
    value (str/int/float): The value to filter by.

    Returns:
    pyspark.sql.DataFrame: The filtered DataFrame.
    """
    return df.filter(F.col(column) == value)

# 1b. Filter by Value
def filter_columns_by_values(df, filters: dict, is_and_operator=True):
    """
    Filters a DataFrame based on a value in specific columns.

    Parameters:
    df (pyspark.sql.DataFrame): The DataFrame to filter.
    filters (dict): A dictionary where the key is the column name and the value is the value to filter by.

    Returns:
    pyspark.sql.DataFrame: The filtered DataFrame.

    Example:
    filter_by_value(df, {"Animal": "cat", "Value": 1})
    """
    conditions = None
    for column, values in filters.items():
        if isinstance(values, list):  # if the value is a list
            condition = F.col(column).isin(values)
        else:  # if the value is not a list
            condition = (F.col(column) == values)
        if conditions is None:
            conditions = condition
        else:
            if is_and_operator:
                conditions = conditions & condition
            else:
                conditions = conditions | condition
    
    return df.filter(conditions)

# 2a. Filter by Category
def filter_column_by_category(df, column, categories):
    """
    Filters a DataFrame based on a category in a specific column.

    Parameters:
    df (pyspark.sql.DataFrame): The DataFrame to filter.
    column (str): The column name to filter on.
    categories (list): The list of categories to filter by.

    Returns:
    pyspark.sql.DataFrame: The filtered DataFrame.
    """
    return df.filter(F.col(column).isin(categories))

# 2b. Filter by Category
def filter_columns_by_categories(df, filters):
    """
    Filters a DataFrame based on a category in specific columns.
    This function allows to filter by multiple categories using OR logic within each column.

    Parameters:
    df (pyspark.sql.DataFrame): The DataFrame to filter.
    filters (dict): A dictionary where the key is the column name and the value is the list of categories to filter by.
        - The value can be a single category or a list of categories.

    Returns:
    pyspark.sql.DataFrame: The filtered DataFrame.

    Example:
    filter_by_category(df, {"Animal": ["cat", "dog"], "Color": "black"})
    """
    for column, categories in filters.items():
        if not isinstance(categories, list):
            categories = [categories]
        df = df.filter(F.col(column).isin(categories))
    return df

# 3a. Filter by Date or Time
def filter_column_by_date_range(df, column, start_date, end_date):
    """
    Filters a DataFrame based on a date range in a specific column.

    Parameters:
    df (pyspark.sql.DataFrame): The DataFrame to filter.
    column (str): The column name to filter on.
    start_date (str): The start date to filter by.
    end_date (str): The end date to filter by.

    Returns:
    pyspark.sql.DataFrame: The filtered DataFrame.
    """
    return df.filter((F.col(column) >= start_date) & (F.col(column) <= end_date))

# 3b. Filter by Date or Time
def filter_columns_by_date_ranges(df, filters):
    """
    Filters a DataFrame based on a date range in specific columns.
    This function allows to filter by multiple date ranges using OR logic within each column.

    Parameters:
    df (pyspark.sql.DataFrame): The DataFrame to filter.
    filters (dict): A dictionary where the key is the column name and the value is a tuple of (start_date, end_date).
        - The value can be a single tuple of (start_date, end_date) or a list of such tuples.

    Returns:
    pyspark.sql.DataFrame: The filtered DataFrame.

    Example:
    filter_by_date_range(df, {"Date": [("2022-01-02", "2022-01-04"), ("2022-01-10", "2022-01-20")]})
    """
    for column, date_ranges in filters.items():
        if not isinstance(date_ranges[0], tuple):  # if single date range is provided
            date_ranges = [date_ranges]
        condition = F.lit(False)
        for start_date, end_date in date_ranges:
            condition |= (F.col(column) >= start_date) & (F.col(column) <= end_date)
        df = df.filter(condition)
    return df

# 3c. Filter by Datetime
def filter_by_time(df, start_time, end_time, time_column='_event_time'):
    """
    Filters a DataFrame based on a specified time range.

    Args:
        df (DataFrame): The input DataFrame to filter.
        start_time (str): The start time of the time range in 'yyyy-MM-dd HH:mm:ss' format.
        end_time (str): The end time of the time range in 'yyyy-MM-dd HH:mm:ss' format.
        time_column (str, optional): The name of the time column. Defaults to 'timestamp'.

    Returns:
        DataFrame: The filtered DataFrame.

    Examples:
        filtered_df = filter_by_time(df, '2023-01-01 00:00:00', '2023-02-01 23:59:59')
    """
    return df.filter((F.col(time_column) >= start_time) & (F.col(time_column) <= end_time))


# 3d. Filter by Relative Datetime
def filter_by_relative_time(df, weeks=0, days=0, hours=0, minutes=0, seconds=0, microseconds=0, milliseconds=0, time_column='_event_time'):
    """
    Filters a DataFrame based on a specified time range relative to the current time.

    Args:
        df (DataFrame): The input DataFrame to filter.
        weeks (int, optional): Number of weeks to subtract from the current time. Defaults to 0.
        days (int, optional): Number of days to subtract from the current time. Defaults to 0.
        hours (int, optional): Number of hours to subtract from the current time. Defaults to 0.
        minutes (int, optional): Number of minutes to subtract from the current time. Defaults to 0.
        seconds (int, optional): Number of seconds to subtract from the current time. Defaults to 0.
        microseconds (int, optional): Number of microseconds to subtract from the current time. Defaults to 0.
        milliseconds (int, optional): Number of milliseconds to subtract from the current time. Defaults to 0.
        time_column (str, optional): The name of the time column. Defaults to 'timestamp'.

    Returns:
        DataFrame: The filtered DataFrame.

    Examples:
        # Filter by the last 5 weeks
        # filtered_df = filter_by_relative_time(df, weeks=5)

        # Filter by the last 1 day and 3 hours
        filtered_df = filter_by_relative_time(df, days=1, hours=3)
    """
    current_time = datetime.now()
    filter_time = current_time - timedelta(weeks=weeks,  days=days, hours=hours, minutes=minutes, seconds=seconds, microseconds=microseconds, milliseconds=milliseconds)
    filter_time_str = filter_time.strftime('%Y-%m-%d %H:%M:%S')
    return df.filter(F.col(time_column) >= filter_time_str)

# 4a. Filter by Null Values
def filter_columns_by_null(df, columns):
    """
    Filters a DataFrame based on null values in specific columns.
    This function allows to filter by multiple columns using OR logic.

    Parameters:
    df (pyspark.sql.DataFrame): The DataFrame to filter.
    columns (list): The list of column names to filter on.

    Returns:
    pyspark.sql.DataFrame: The filtered DataFrame.

    Example:
    filter_by_null(df, ["Animal", "Color"])
    """
    condition = F.lit(False)
    for column in columns:
        condition |= F.col(column).isNull()
    df = df.filter(condition)
    return df

# 4b. Filter by Null Values
def filter_columns_by_null(df, columns):
    """
    Filters a DataFrame based on null values in specific columns.

    Parameters:
    df (pyspark.sql.DataFrame): The DataFrame to filter.
    columns (list): The list of column names to filter on.

    Returns:
    pyspark.sql.DataFrame: The filtered DataFrame.

    Example:
    filter_by_null(df, ["Animal"])
    """
    for column in columns:
        df = df.filter(F.col(column).isNull())
    return df

# 5a. Filter by String Pattern
def filter_column_by_string_pattern(df, column, pattern):
    """
    Filters a DataFrame based on a string pattern in a specific column.

    Parameters:
    df (pyspark.sql.DataFrame): The DataFrame to filter.
    column (str): The column name to filter on.
    pattern (str): The string pattern to filter by.

    Returns:
    pyspark.sql.DataFrame: The filtered DataFrame.
    """
    return df.filter(F.col(column).rlike(pattern))

# 5. Filter by String Pattern
def filter_columns_by_string_pattern(df, filters):
    """
    Filters a DataFrame based on a string pattern in specific columns.
    If multiple patterns are provided for a column, the function uses OR logic.

    Parameters:
    df (pyspark.sql.DataFrame): The DataFrame to filter.
    filters (dict): A dictionary where the key is the column name and the value is the string pattern to filter by.

    Returns:
    pyspark.sql.DataFrame: The filtered DataFrame.

    Example:
    filter_by_string_pattern(df, {"Animal": ["^c.*", "^d.*"]})  
    # returns rows where Animal starts with "c" or "d"
    """
    for column, patterns in filters.items():
        condition = F.lit(False)
        for pattern in patterns:
            condition |= F.col(column).rlike(pattern)
        df = df.filter(condition)
    return df

# 6a. Filter by Multiple Conditions
def filter_column_by_multiple_conditions(df, condition1, condition2):
    """
    Filters a DataFrame based on multiple conditions.

    Parameters:
    df (pyspark.sql.DataFrame): The DataFrame to filter.
    condition1 (Column): The first condition to filter by.
    condition2 (Column): The second condition to filter by.

    Returns:
    pyspark.sql.DataFrame: The filtered DataFrame.
    """
    return df.filter(condition1 & condition2)

# 6b. Filter by Multiple Conditions
def filter_columns_by_multiple_conditions(df, conditions):
    """
    Filters a DataFrame based on multiple conditions.
    If multiple conditions are provided, the function uses OR logic.

    Parameters:
    df (pyspark.sql.DataFrame): The DataFrame to filter.
    conditions (list): The list of conditions to filter by.

    Returns:
    pyspark.sql.DataFrame: The filtered DataFrame.

    Example:
    filter_by_multiple_conditions(df, [(F.col("Animal") == "cat"), (F.col("Value") > 2)])  
    # returns rows where Animal is "cat" or Value is greater than 2
    """
    condition = F.lit(False)
    for cond in conditions:
        condition |= cond
    df = df.filter(condition)
    return df

# 7a. Filter by a Custom Function
def filter_column_by_custom_function(df, column, function):
    """
    Filters a DataFrame based on a custom function applied to a specific column.

    Parameters:
    df (pyspark.sql.DataFrame): The DataFrame to filter.
    column (str): The column name to filter on.
    function (function): The custom function to filter by.

    Returns:
    pyspark.sql.DataFrame: The filtered DataFrame.
    """
    return df.filter(function(F.col(column)))


# 7. Filter by a Custom Function
def filter_columns_by_custom_function(df, filters):
    """
    Filters a DataFrame based on a custom function applied to specific columns.
    If multiple functions are provided for a column, the function uses OR logic.

    Parameters:
    df (pyspark.sql.DataFrame): The DataFrame to filter.
    filters (dict): A dictionary where the key is the column name and the value is the custom function to filter by.

    Returns:
    pyspark.sql.DataFrame: The filtered DataFrame.

    Example:
    filter_by_custom_function(df, {"Value": [lambda x: x > 3, lambda x: x < 1]})  
    # returns rows where Value is greater than 3 or less than 1
    """
    for column, functions in filters.items():
        condition = F.lit(False)
        for function in functions:
            condition |= function(F.col(column))
        df = df.filter(condition)
    return df


# COMMAND ----------

from pyspark.sql import functions as F
from pyspark.sql.window import Window
from datetime import datetime, timedelta

# This function filters a DataFrame based on a pattern in a specific column


def pattern_based_rule(df, column, pattern):
    """
    Filters a DataFrame based on a pattern in a specific column.

    Parameters:
    df (pyspark.sql.DataFrame): The DataFrame to filter.
    column (str): The column name to filter on.
    pattern (str): The pattern to match.

    Returns:
    pyspark.sql.DataFrame: The filtered DataFrame.
    """

    # Filter the DataFrame where the column equals the pattern
    return df.filter(F.col(column) == pattern)

# This function groups a DataFrame by a column and filters based on a count threshold


def threshold_based_rule(df, threshold, groupby_column=None, sum_column=None):
    """
    Groups a DataFrame by a column and filters based on a count threshold.

    Parameters:
    df (pyspark.sql.DataFrame): The DataFrame to group and filter.
    threshold (int): The count threshold for filtering.
    groupby_column (str, optional): The column name to group by. Default is None.
    sum_column (str, optional): The column name to sum the values of. Defaults to None (counts all rows in each group).

    Returns:
    pyspark.sql.DataFrame: The grouped and filtered DataFrame.
    """

    # The name of the optional temporary column to hold the truncated timestamp
    default_sum_column_name = 'sum_column_tmp'

    # Create a dummy summation column if the 'count_column' is None
    if sum_column is None:
        df = df.withColumn(default_sum_column_name, F.lit(1))
        sum_column = default_sum_column_name

    # if the 'groupby_column' is not None, group the DataFrame by the groupby_column, count the rows in each group
    if groupby_column is not None:
        df =  df.groupBy(groupby_column).agg(F.sum(F.col(sum_column)).alias(sum_column))

    # Filter the groups where the count is greater than the threshold
    return df.filter(F.col(sum_column) > threshold)

# This function groups a DataFrame by multiple columns and filters based on a count threshold


def threshold_based_rule_multiple_group_by(df, groupby_columns, threshold, sum_column=None):
    """
    Groups a DataFrame by multiple columns and filters based on a count threshold.

    Parameters:
    df (pyspark.sql.DataFrame): The DataFrame to group and filter.
    groupby_columns (list of str): The column names to group by.
    threshold (int): The count threshold for filtering.
    sum_column (str, optional): The column to sum up in relation to the threshold. Defaults to None (counts all rows in each group).

    Returns:
    pyspark.sql.DataFrame: The grouped and filtered DataFrame.
    """
    default_sum_column_name = 'count_column_tmp'

    # Create a dummy summation column if the 'sum_column' is None
    if sum_column is None:
        df = df.withColumn(default_sum_column_name, F.lit(1))
        sum_column = default_sum_column_name

    # Group the DataFrame by the groupby_column, count the rows in each group,
    # and filter the groups where the count is greater than the threshold
    return df.groupBy(*groupby_columns).agg(F.sum(F.col(sum_column)).alias(sum_column+'_total')).filter(F.col(sum_column+'_total') > threshold)


# This function detects statistical anomalies in a DataFrame based on a z-score threshold
def statistical_anomaly_detection(df, comparitive_column, z_score_threshold=3.0):
    """
    Detects statistical anomalies in a DataFrame based on a z-score threshold.

    Parameters:
    df (pyspark.sql.DataFrame): The DataFrame to analyze.
    comparitive_column (str): The column name to compute the z-score on.
    z_score_threshold (float, optional): The z-score threshold for anomaly detection. Defaults to 3.0.

    Returns:
    pyspark.sql.DataFrame: The DataFrame filtered to only include rows considered to be anomalies.
    """

    # Calculate the mean and standard deviation of the comparitive_column
    stats = df.select(F.mean(F.col(comparitive_column)).alias('mean'), F.stddev(
        F.col(comparitive_column)).alias('stddev')).collect()[0]
    
    # Filter the DataFrame where the absolute difference between the comparitive_column and the mean
    # is greater than the z_score_threshold times the standard deviation
    df = df.filter(F.abs(F.col(comparitive_column) - stats['mean']) > z_score_threshold * stats['stddev'])
    df = df.withColumn("Mean", lit(stats['mean'])).withColumn("stddev", lit(stats['stddev']))

    return df

def statistical_anomaly_detection_group_by(df, group_by_column, sum_column=None, no_minimum_window_events=None, current_window_is_multiple_of_mean=2.0, z_score_threshold=3.0):
    """
    Detects statistical anomalies in a DataFrame based on a z-score threshold.

    Parameters:
    df (pyspark.sql.DataFrame): The DataFrame to analyze.
    group_by_column (str): The column name to group by.
    sum_column (str, optional): The column name to compute the z-score on. Defaults to None.
    no_minimum_window_events (int, optional): The minimum number of samples that are in all group_by_column entries. Default is None.
    current_window_is_multiple_of_mean (float, optional): The minimum multiple that the sum_column must be from the mean so that small increases aren't alerted. Default is 2.0.
    z_score_threshold (float, optional): The z-score threshold for anomaly detection. Defaults to 3.0.

    Returns:
    pyspark.sql.DataFrame: The DataFrame filtered to only include rows considered to be anomalies.
    """

    # The name of the optional temporary column to hold the truncated timestamp
    default_sum_column_name = 'sum_column_tmp'

    # Create a dummy summation column if the 'count_column' is None
    if sum_column is None:
        df = df.withColumn(default_sum_column_name, F.lit(1))
        sum_column = default_sum_column_name

    # Calculate the mean and standard deviation of the sum_column for each group
    df = df.groupby(group_by_column).agg(
        F.count(F.col(group_by_column)).alias('no_events'),
        F.sum(sum_column).alias(sum_column)
    )

    df = statistical_anomaly_detection(df=df, comparitive_column=sum_column, z_score_threshold=z_score_threshold)
    
    if no_minimum_window_events is not None:
        df = df.filter(F.col('no_events') >= no_minimum_window_events)

    if current_window_is_multiple_of_mean is not None and current_window_is_multiple_of_mean > 0:
        df = df.filter(F.col(sum_column) >= F.col('Mean') * current_window_is_multiple_of_mean)
    return df


# This function detects trends in a DataFrame based on a ratio threshold and time ranges


def trending_based_rule(df, timestamp_column, partition_column, count_column=None, ratio_threshold=1.25, hour_range=-3600, day_range=-86400):
    """
    Detects trends in a DataFrame based on a ratio threshold and time ranges.

    Parameters:
    df (pyspark.sql.DataFrame): The DataFrame to analyze.
    timestamp_column (str): The column name containing the timestamp.
    partition_column (str): The column name for partitioning the data.
    count_column (int or long, optional): The column name containing the numeric value to compute the average on.
    ratio_threshold (float, optional): The ratio threshold for trend detection. Defaults to 1.25.
    hour_range (int, optional): The range in seconds to compute the hourly average. Defaults to -3600.
    day_range (int, optional): The range in seconds to compute the daily average. Defaults to -86400.

    Returns:
    pyspark.sql.DataFrame: The DataFrame filtered to only include rows considered to be trending.
    """

    # If the count column is None then create a column with a count of 1, otherwise use it
    if count_column is None:
        df = df.withColumn("db_count_column_tmp", F.lit(1))
        count_column = "db_count_column_tmp"

    # First, group by the partition column and the timestamp column, and calculate the sum for each group
    grouped_df = df.groupBy(partition_column, timestamp_column).agg(
        F.sum(count_column).alias('sum_count'))

    # Then define a window ordered by the timestamp_column and partitioned by the partition_column
    window = Window.partitionBy(partition_column).orderBy(
        F.col(timestamp_column).cast("long"))

    # Calculate the average of the sum_count over the past hour for each row
    grouped_df = grouped_df.withColumn('hour_avg', F.avg(
        F.col('sum_count')).over(window.rangeBetween(hour_range, 0)))
    # Calculate the average of the sum_count over the past day for each row
    grouped_df = grouped_df.withColumn('day_avg', F.avg(
        F.col('sum_count')).over(window.rangeBetween(day_range, 0)))

    # Filter the DataFrame where the hour average is greater than the ratio_threshold times the day average
    df = grouped_df.filter(
        F.col('hour_avg') > ratio_threshold * F.col('day_avg'))

    # Group by the partition_column and select the min and max timestamp, sum of count_column, and the hour_avg and day_avg
    df = df.groupBy(partition_column).agg(
        F.min(timestamp_column).alias("min_timestamp"),
        F.max(timestamp_column).alias("max_timestamp"),
        F.first("sum_count").alias("sum_count"),
        F.first("hour_avg").alias("hour_avg"),
        F.first("day_avg").alias("day_avg")
    )

    return df


def statistically_significant_window_by_std(df, comparative_column: str, timestamp_column: str = '_event_time', z_score_threshold: float = 3.0, count_column=None, window='day', no_minimum_window_events=0, current_window_is_multiple_of_mean=2.0):
    """
    This function identifies the records in the input dataframe `df` where the count of events in the last window of time
    (as specified by the `window` parameter) is statistically significantly higher than the mean count of events in previous windows.
    The measure of statistical significance is determined by a z-score threshold.

    Parameters:
    df: A DataFrame containing the data to be analyzed.
    comparative_column (str): The name of the column by which to group the records for comparison.
    timestamp_column (str): The name of the column in the DataFrame that contains the timestamp of each record. Defalut is '_event_time'.
    z_score_threshold (float): The minimum z-score for a count of events to be considered statistically significant. Default is 3.0.
    count_column (str): If this value is populated, the method will sum the values in 'count_column' instead of creating a dummy column with the value 1 in it.
    window (str): The window of time to consider for the analysis. Default is 'day'.
    no_minimum_window_events (int): The minimum number of historic windows with values the comparative_column should have. Default is 0.
    current_window_is_multiple_of_mean (float): This filters for rows who's current window is a multiple of their mean value to remove statistically significant but small.

    Returns:
    None. This function does not return a value; it displays the resulting DataFrame.
    """

    # Create a temporary column to hold the truncated timestamp
    truncated_date_column_name = "date_trucated_tmp"
    default_count_column_name = 'count_column_tmp'

    # Create a dummy summation column if the 'count_column' is None
    if count_column is None:
        df = df.withColumn(default_count_column_name, F.lit(1))
        count_column = default_count_column_name

    # Calculate the timestamp for the start of the current window (hour, by default)
    current_window = F.date_trunc(window, F.current_timestamp())

    # Add a new column to df that contains the truncated timestamp of each record
    df = df.withColumn(truncated_date_column_name, F.date_trunc(window, F.col(timestamp_column)))

    # Add two new columns to df to track the number of events in the last window and before the last window
    df = df.withColumn(f"events_in_last_{window}", F.when(F.col(
        truncated_date_column_name) == current_window, F.col(count_column)).otherwise(0))
    df = df.withColumn(f"events_before_last_{window}", F.when(F.col(
        truncated_date_column_name) < current_window, F.col(count_column)).otherwise(0))

    # Group df by the comparative column and the truncated timestamp, and calculate the sum of events in the last window and before the last window
    df = df.groupBy(comparative_column, truncated_date_column_name).agg(
        F.sum(f"events_in_last_{window}").alias(f"events_in_last_{window}"),
        F.sum(f"events_before_last_{window}").alias(
            f"events_before_last_{window}")
    )

    # Group df by the comparative column and calculate various statistics for the events before the last window
    df = df.groupBy(comparative_column).agg(
        F.sum(f"events_in_last_{window}").alias(f"events_in_last_{window}"),
        F.mean(f"events_before_last_{window}").alias(
            f"events_before_last_{window}_mean"),
        F.stddev(f"events_before_last_{window}").alias(
            f"events_before_last_{window}_std"),
        F.count(f"events_before_last_{window}").alias(
            f"no_{window}_with_events")
    )

    # Calculate the z-score for each group
    df = df.withColumn("z_score", (F.col(f"events_in_last_{window}") - F.col(
        f"events_before_last_{window}_mean")) / F.col(f"events_before_last_{window}_std"))

    # Filter df to include rows where the z-score is greater than the specified threshold
    # Optionally, you can filter the minimum number of historic event windows (e.g., I have printed 3 of the last seven days)
    # and (optionally) you can filter if today's value is at least `current_window_is_multiple_of_mean` times its mean (e.g., 2 failed logins compared to the mean of .5 is statistically significant but not important so don't
    # alert).
    window_minimum_size = current_window_is_multiple_of_mean * \
        F.col(f"events_before_last_{window}_mean")
    df = df.filter((F.col("z_score") > z_score_threshold) & (F.col(
        f"no_{window}_with_events") > no_minimum_window_events) & (F.col(f"events_in_last_{window}") > window_minimum_size))

    # return the dataframe
    return df
