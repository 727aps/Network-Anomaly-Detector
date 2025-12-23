import pandas as pd

# Load predictions
df = pd.read_csv("test_predictions.csv")

# Check unique anomaly types
print(df["Predicted_ALERT"].value_counts())

# Display first 10 rows where anomalies are detected
print(df[df["Predicted_ALERT"] != "Unknown"].head(10))
