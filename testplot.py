import pandas as pd
import joblib
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.exceptions import NotFittedError

"""
This script loads a pre-trained Random Forest model and its associated preprocessors,
loads a test dataset, preprocesses it, makes predictions, and then visualizes
the distribution of these predictions.
"""

try:
    rf_model = joblib.load("rf_model.pkl")
    encoder = joblib.load("encoder.pkl")
    scaler = joblib.load("scaler.pkl")
    label_encoder = joblib.load("label_encoder.pkl")
    print("✅ Model and preprocessors loaded successfully.")
except FileNotFoundError as e:
    print(f"❌ Error: {e}. Ensure that the model and preprocessors are saved correctly.")
    exit()

try:
    df_test = pd.read_csv(r"C:\Users\APARNA S\Documents\CN_PACKAGE\dataset\test_net.csv", nrows=1000)
    print("✅ Test dataset loaded successfully.")
except Exception as e:
    print(f"❌ Error loading test dataset: {e}")
    exit()

expected_features = list(scaler.feature_names_in_)

for col in expected_features:
    if col not in df_test.columns:
        df_test[col] = 0

df_test = df_test[expected_features]

categorical_cols = list(encoder.feature_names_in_)
numeric_cols = list(scaler.feature_names_in_)

for col in categorical_cols:
    df_test[col] = df_test[col].astype(str)

for col in categorical_cols:
    df_test[col] = df_test[col].apply(lambda x: x if x in encoder.categories_[categorical_cols.index(col)] else "Unknown")

try:
    df_test[categorical_cols] = encoder.transform(df_test[categorical_cols])
except ValueError as e:
    print(f"❌ Encoding Error: {e}")
    exit()

try:
    df_test[numeric_cols] = scaler.transform(df_test[numeric_cols])
except ValueError as e:
    print(f"❌ Scaling Error: {e}")
    exit()

try:
    predictions = rf_model.predict(df_test)
except Exception as e:
    print(f"❌ Prediction Error: {e}")
    exit()

decoded_predictions = label_encoder.inverse_transform(predictions)

output_file = "test_predictions.csv"
df_test["Predicted_ALERT"] = decoded_predictions
df_test.to_csv(output_file, index=False)
print("\n✅ Predictions completed successfully. Results saved to 'test_predictions.csv'.")

plt.figure(figsize=(8, 5))
sns.set_style("whitegrid")

fig = sns.countplot(x=decoded_predictions, palette="viridis")
fig.set_title('Predictions Distribution on the Test Set', fontsize=14, fontweight='bold')
fig.set_xlabel('Predicted Class', fontsize=12)
fig.set_ylabel('Count', fontsize=12)
fig.set_xticklabels(fig.get_xticklabels(), rotation=45)

print("\n🔍 Prediction Counts Per Class:\n", pd.Series(decoded_predictions).value_counts())

plt.show()