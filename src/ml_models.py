import joblib
import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.preprocessing import MinMaxScaler, OneHotEncoder, LabelEncoder
from sklearn.ensemble import IsolationForest
from src.utils import log_alert
import os

class MLModelManager:
    """
    Manages loading, preprocessing, and prediction with various ML models.
    Supports Isolation Forest and LSTM models.
    """
    def __init__(self, models_dir="data/models"):
        self.models_dir = models_dir
        self.models = {}
        self.scalers = {}
        self.encoders = {}
        self.label_encoders = {}
        self.active_model_name = None
        self.active_model = None
        self.active_scaler = None
        self.active_encoder = None
        self.active_label_encoder = None

    def load_model(self, model_name: str):
        """
        Loads the specified ML model and its associated preprocessors.
        Supported models: 'IsolationForest', 'LSTM'.
        """
        model_path = os.path.join(self.models_dir, f"{model_name}.pkl")
        scaler_path = os.path.join(self.models_dir, f"{model_name}_scaler.pkl")
        encoder_path = os.path.join(self.models_dir, f"{model_name}_encoder.pkl")
        label_encoder_path = os.path.join(self.models_dir, f"{model_name}_label_encoder.pkl")

        try:
            if model_name == 'IsolationForest':
                self.models[model_name] = joblib.load(model_path)
                self.scalers[model_name] = joblib.load(scaler_path)
                self.encoders[model_name] = joblib.load(encoder_path)
                self.label_encoders[model_name] = joblib.load(label_encoder_path)
                log_alert(f"Successfully loaded Isolation Forest model and preprocessors.", level='INFO')
            elif model_name == 'LSTM':
                self.models[model_name] = tf.keras.models.load_model(os.path.join(self.models_dir, "lstm_model.h5"))
                self.scalers[model_name] = joblib.load(scaler_path)
                self.encoders[model_name] = joblib.load(encoder_path)
                self.label_encoders[model_name] = joblib.load(label_encoder_path)
                log_alert(f"Successfully loaded LSTM model and preprocessors.", level='INFO')
            else:
                log_alert(f"Unsupported model name: {model_name}", level='ERROR')
                return False
            
            self.active_model_name = model_name
            self.active_model = self.models[model_name]
            self.active_scaler = self.scalers[model_name]
            self.active_encoder = self.encoders[model_name]
            self.active_label_encoder = self.label_encoders[model_name]

            return True
        except FileNotFoundError as e:
            log_alert(f"Error loading model or preprocessor for {model_name}: {e}. Please ensure files exist in {self.models_dir}", level='ERROR')
            return False
        except Exception as e:
            log_alert(f"An unexpected error occurred while loading {model_name}: {e}", level='ERROR')
            return False

    def preprocess_features(self, features: pd.DataFrame) -> pd.DataFrame:
        """
        Preprocesses the input features using the active scaler and encoder.
        """
        if self.active_scaler is None or self.active_encoder is None:
            log_alert("Scaler or Encoder not loaded. Cannot preprocess features.", level='ERROR')
            return None

        numeric_cols = features.select_dtypes(include=np.number).columns
        categorical_cols = features.select_dtypes(include='object').columns

        scaled_numeric_features = self.active_scaler.transform(features[numeric_cols])
        scaled_df = pd.DataFrame(scaled_numeric_features, columns=numeric_cols, index=features.index)

        encoded_categorical_features = self.active_encoder.transform(features[categorical_cols])
        encoded_df = pd.DataFrame(encoded_categorical_features, columns=self.active_encoder.get_feature_names_out(categorical_cols), index=features.index)

        preprocessed_df = pd.concat([scaled_df, encoded_df], axis=1)

        return preprocessed_df

    def predict(self, features: pd.DataFrame):
        """
        Makes a prediction using the active model.
        Returns anomaly score for Isolation Forest, or class labels for LSTM.
        """
        if self.active_model is None:
            log_alert("No active model loaded. Cannot make predictions.", level='ERROR')
            return None

        preprocessed_features = self.preprocess_features(features)
        if preprocessed_features is None:
            return None
        
        if self.active_model_name == 'IsolationForest':
            return self.active_model.decision_function(preprocessed_features) * -1
        elif self.active_model_name == 'LSTM':
            num_features = preprocessed_features.shape[1]
            timesteps = 1
            lstm_input = preprocessed_features.values.reshape((-1, timesteps, num_features))
            
            probabilities = self.active_model.predict(lstm_input)
            predictions = np.argmax(probabilities, axis=1)
            return self.active_label_encoder.inverse_transform(predictions)
        
        return None