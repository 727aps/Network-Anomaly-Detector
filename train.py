import pandas as pd
import joblib
from sklearn.preprocessing import OrdinalEncoder, MinMaxScaler, LabelEncoder
from sklearn.exceptions import NotFittedError

# 📌 Load Model & Preprocessors
try:
    rf_model = joblib.load("rf_model.pkl")
    encoder = joblib.load("encoder.pkl")
    scaler = joblib.load("scaler.pkl")
    label_encoder = joblib.load("label_encoder.pkl")
    print("✅ Model and preprocessors loaded successfully.")
except FileNotFoundError as e:
    print(f"❌ Error: {e}. Ensure that the model and preprocessors are saved correctly.")
    exit()

# 📌 Load Test Dataset
try:
    df_test = pd.read_csv(r"C:\Users\APARNA S\Documents\CN_PACKAGE\dataset\test_net.csv", nrows=1000)
    print("✅ Test dataset loaded successfully.")
except Exception as e:
    print(f"❌ Error loading test dataset: {e}")
    exit()

# 📌 Ensure Test Data Has the Same Columns & Order as Training
expected_features = list(scaler.feature_names_in_)  # All expected features

# Add missing columns with default values
for col in expected_features:
    if col not in df_test.columns:
        df_test[col] = 0  # Default for numerical columns

# Ensure order matches training data
df_test = df_test[expected_features]

# 📌 Identify Categorical and Numeric Columns
categorical_cols = list(encoder.feature_names_in_)  # Trained categorical columns
numeric_cols = list(scaler.feature_names_in_)  # Trained numerical columns

# Convert categorical columns to string
for col in categorical_cols:
    df_test[col] = df_test[col].astype(str)

# 📌 Handle Unseen Categories by Assigning "Unknown"
for col in categorical_cols:
    df_test[col] = df_test[col].apply(lambda x: x if x in encoder.categories_[categorical_cols.index(col)] else "Unknown")

# 📌 Encode Categorical Features
try:
    df_test[categorical_cols] = encoder.transform(df_test[categorical_cols])
except ValueError as e:
    print(f"❌ Encoding Error: {e}")
    exit()

# 📌 Scale Numerical Features
try:
    df_test[numeric_cols] = scaler.transform(df_test[numeric_cols])
except ValueError as e:
    print(f"❌ Scaling Error: {e}")
    exit()

# 📌 Make Predictions
try:
    predictions = rf_model.predict(df_test)
except Exception as e:
    print(f"❌ Prediction Error: {e}")
    exit()

# 📌 Decode Predictions
decoded_predictions = label_encoder.inverse_transform(predictions)

# 📌 Save Predictions to CSV
output_file = "test_predictions.csv"
df_test["Predicted_ALERT"] = decoded_predictions
df_test.to_csv(output_file, index=False)

print("\n✅ Predictions completed successfully. Results saved to 'test_predictions.csv'.")
print(decoded_predictions[:10])  # Print first 10 predictions
