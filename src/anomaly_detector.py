import pandas as pd
from src.ml_models import MLModelManager
from src.utils import log_alert

class AnomalyDetector:
    """
    Performs hybrid anomaly detection by combining rule-based logic with ML model predictions.
    """
    def __init__(self, ml_model_manager: MLModelManager, threshold: float = 0.7):
        self.ml_model_manager = ml_model_manager
        self.threshold = threshold

    def _rule_based_detection(self, features: dict) -> str:
        """
        Applies rule-based checks for common network attacks.
        """
        anomaly_type = "Normal"

        if features.get('packet_size', 0) > 250 and features.get('rate', 0) > 100:
            anomaly_type = 'DDoS Attack'
        
        if features.get('ct_dst_sport_ltm', 0) > 3 and features.get('spkts', 0) < 10:
            anomaly_type = 'Port Scanning'

        if features.get('protocol', 0) not in [6, 17] and features.get('payload_len', 0) > 0:
            anomaly_type = 'Intrusion Detected'

        if features.get('packet_size', 0) > 2000:
            anomaly_type = 'Malicious Traffic'

        payload = features.get('payload', '').lower()
        sql_keywords = ['union select', 'drop table', 'select *', '--', 'insert into', 'exec']
        if any(keyword in payload for keyword in sql_keywords):
            anomaly_type = 'SQL Injection Attempt'

        return anomaly_type

    def detect(self, features: dict) -> tuple[str, float]:
        """
        Performs hybrid anomaly detection using rule-based logic and ML models.
        Returns (anomaly_label, anomaly_score).
        """
        rule_based_label = self._rule_based_detection(features)
        ml_anomaly_score = 0.0
        ml_anomaly_label = "Normal"

        if self.ml_model_manager.active_model:
            try:
                features_df = pd.DataFrame([features])
                
                ml_prediction = self.ml_model_manager.predict(features_df)

                if self.ml_model_manager.active_model_name == 'IsolationForest':
                    ml_anomaly_score = ml_prediction[0]
                    ml_anomaly_label = "ML Anomaly" if ml_anomaly_score > self.threshold else "Normal"
                elif self.ml_model_manager.active_model_name == 'LSTM':
                    ml_anomaly_label = ml_prediction[0]
                    ml_anomaly_score = 1.0 if ml_anomaly_label != 'Normal' else 0.0

            except Exception as e:
                log_alert(f"Error during ML prediction: {e}", level='ERROR')

        final_anomaly_label = rule_based_label
        final_anomaly_score = ml_anomaly_score

        if rule_based_label != "Normal" and ml_anomaly_label != "Normal":
            final_anomaly_label = f"Hybrid: {rule_based_label} / {ml_anomaly_label}"
            final_anomaly_score = max(ml_anomaly_score, 0.8)
        elif rule_based_label != "Normal":
            final_anomaly_label = rule_based_label
            final_anomaly_score = max(ml_anomaly_score, 0.6)
        elif ml_anomaly_label != "Normal":
            final_anomaly_label = ml_anomaly_label

        return final_anomaly_label, final_anomaly_score