import joblib
import pandas as pd
import numpy as np
import tensorflow as tf
from sklearn.preprocessing import MinMaxScaler, OneHotEncoder, LabelEncoder
from sklearn.ensemble import IsolationForest
from src.utils import log_alert
import os

class MLModelManager:
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
