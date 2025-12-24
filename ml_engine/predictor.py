import joblib
import os
import logging
from .feature_extractor import FeatureExtractor

logger = logging.getLogger("ml_engine")

class PhishingPredictor:
    def __init__(self, model_path="models/best_model.joblib"):
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"ML Model not found at {model_path}. Please train and save it first.")
        
        logger.info("Loading ML model...")
        data = joblib.load(model_path)
        self.model = data['model']
        self.scaler = data['scaler']
        self.extractor = FeatureExtractor()
        
        # Label mapping from notebook: 0=Benign, 1=Phishing, 2=Suspected
        self.labels = {0: "Legitimate", 1: "Phishing", 2: "Suspected"}

    def predict(self, url):
        try:
            # 1. Extract
            features_df = self.extractor.extract(url)
            
            # 2. Scale
            X_scaled = self.scaler.transform(features_df)
            
            # 3. Predict
            pred_idx = self.model.predict(X_scaled)[0]
            probs = self.model.predict_proba(X_scaled)[0]
            
            confidence = float(probs[pred_idx])
            label = self.labels.get(pred_idx, "Unknown")
            
            return label, confidence
        except Exception as e:
            logger.error(f"Prediction failed for {url}: {e}")
            return "Error", 0.0