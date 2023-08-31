# Databricks notebook source
df = spark.sql("SELECT * FROM delta.`/tmp/detection_maturity/tables/url_filtering`")
df.display()
