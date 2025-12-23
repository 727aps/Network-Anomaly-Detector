import pandas as pd
import joblib
from sklearn.preprocessing import OrdinalEncoder, MinMaxScaler, LabelEncoder
from sklearn.exceptions import NotFittedError

def load_model_and_preprocessors():
    """
    Loads the pre-trained Random Forest model and associated preprocessors.
    """
    try:
        rf_model = joblib.load("rf_model.pkl")
        encoder = joblib.load("encoder.pkl")
        scaler = joblib.load("scaler.pkl")
        label_encoder = joblib.load("label_encoder.pkl")
        print("✅ Model and preprocessors loaded successfully.")
        return rf_model, encoder, scaler, label_encoder
    except FileNotFoundError as e:
        print(f"❌ Error: {e}. Ensure that the model and preprocessors are saved correctly.")
        exit()

def load_test_dataset():
    """
    Loads the test dataset.
    """
    try:
        df_test = pd.read_csv(r"C:\Users\APARNA S\Documents\CN_PACKAGE\dataset\test_net.csv", nrows=1000)
        print("✅ Test dataset loaded successfully.")
        return df_test
    except Exception as e:
        print(f"❌ Error loading test dataset: {e}")
        exit()

def preprocess_test_data(df_test, encoder, scaler, expected_features, categorical_cols, numeric_cols, label_encoder):
    """
    Preprocesses the test data to match the training data format.
    """
    for col in expected_features:
        if col not in df_test.columns:
            df_test[col] = 0
    df_test = df_test[expected_features]

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
    return df_test

def make_predictions(rf_model, df_test, label_encoder):
    """
    Makes predictions using the loaded model and decodes them.
    """
    try:
        predictions = rf_model.predict(df_test)
    except Exception as e:
        print(f"❌ Prediction Error: {e}")
        exit()
    decoded_predictions = label_encoder.inverse_transform(predictions)
    return decoded_predictions

def save_predictions(df_test, decoded_predictions, output_file="test_predictions.csv"):
    """
    Saves the predictions to a CSV file.
    """
    df_test["Predicted_ALERT"] = decoded_predictions
    df_test.to_csv(output_file, index=False)
    print("\n✅ Predictions completed successfully. Results saved to 'test_predictions.csv'.")
    print(decoded_predictions[:10])

if __name__ == "__main__":
    rf_model, encoder, scaler, label_encoder = load_model_and_preprocessors()
    df_test = load_test_dataset()

    expected_features = list(scaler.feature_names_in_)
    categorical_cols = list(encoder.feature_names_in_)
    numeric_cols = list(scaler.feature_names_in_)

    df_test = preprocess_test_data(df_test, encoder, scaler, expected_features, categorical_cols, numeric_cols, label_encoder)
    decoded_predictions = make_predictions(rf_model, df_test, label_encoder)
    save_predictions(df_test, decoded_predictions)
