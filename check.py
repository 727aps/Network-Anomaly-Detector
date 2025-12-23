import pandas as pd

"""
This script loads the anomaly detection predictions from 'test_predictions.csv',
prints the count of unique anomaly types, and displays the first 10 rows
where anomalies were detected.
"""

df = pd.read_csv("test_predictions.csv")
print(df["Predicted_ALERT"].value_counts())
print(df[df["Predicted_ALERT"] != "Unknown"].head(10))