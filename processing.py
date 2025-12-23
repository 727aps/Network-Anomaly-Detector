import pandas as pd
from sklearn.preprocessing import OrdinalEncoder, MinMaxScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# 📌 Load train and test datasets
train_df = pd.read_csv(r"C:\Users\APARNA S\Documents\CN_PACKAGE\dataset\train_net.csv", nrows=1000)
test_df = pd.read_csv(r"C:\Users\APARNA S\Documents\CN_PACKAGE\dataset\test_net.csv", nrows=1000)

print("Train set size:", train_df.shape)
print("Test set size:", test_df.shape)

# 📌 Identify categorical columns
categorical_cols = train_df.select_dtypes(include=['object']).columns.tolist()
target_column = 'ALERT'

# Remove 'ALERT' from categorical columns (since it's the target)
if target_column in categorical_cols:
    categorical_cols.remove(target_column)

# Ensure categorical columns exist in test data
categorical_cols = [col for col in categorical_cols if col in test_df.columns]

# 📌 Encode categorical features
encoder = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
train_df[categorical_cols] = encoder.fit_transform(train_df[categorical_cols])
test_df[categorical_cols] = encoder.transform(test_df[categorical_cols])

# 📌 Encode Target Column (ALERT)
if target_column in train_df.columns:
    train_df[target_column] = train_df[target_column].fillna("Unknown")  # Handle NaNs
    label_encoder = LabelEncoder()
    train_df[target_column] = label_encoder.fit_transform(train_df[target_column])
    print("\nUnique Target Labels (Encoded):", label_encoder.classes_)

# 📌 Feature Scaling (MinMaxScaler)
numeric_cols = train_df.select_dtypes(include=['number']).columns.tolist()
if target_column in numeric_cols:
    numeric_cols.remove(target_column)

scaler = MinMaxScaler()
train_df[numeric_cols] = scaler.fit_transform(train_df[numeric_cols])

numeric_cols_test = [col for col in numeric_cols if col in test_df.columns]
test_df[numeric_cols_test] = scaler.transform(test_df[numeric_cols_test])

print("\nData after scaling:\n", train_df.head())

# 📌 Split Data into Features (X) and Target (y)
X_train = train_df.drop(columns=[target_column])
y_train = train_df[target_column]

# Ensure test dataset handling
if target_column in test_df.columns:
    test_df[target_column] = test_df[target_column].fillna("Unknown")
    test_df[target_column] = label_encoder.transform(test_df[target_column])
    X_test = test_df.drop(columns=[target_column])
    y_test = test_df[target_column]
else:
    X_test = test_df
    y_test = None

print("\nData split into features (X) and target (y)")
print("X_train shape:", X_train.shape)
print("y_train shape:", y_train.shape)

# -------------------------------------------
# ✅ Model Training: Random Forest Classifier
# -------------------------------------------

# 📌 Split Train Data into Training & Validation (80-20 split)
X_train_split, X_val, y_train_split, y_val = train_test_split(X_train, y_train, test_size=0.2, random_state=42)

# 📌 Train the Random Forest Model
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train_split, y_train_split)

# 📌 Validate Model Performance
y_pred = rf_model.predict(X_val)

# 📌 Evaluate Accuracy & Metrics
print("\nModel Accuracy:", accuracy_score(y_val, y_pred))
print("\nClassification Report:\n", classification_report(y_val, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_val, y_pred))

# 📌 Predict on Test Data (If Labels Exist)
if y_test is not None:
    y_test_pred = rf_model.predict(X_test)
    print("\nTest Set Accuracy:", accuracy_score(y_test, y_test_pred))
