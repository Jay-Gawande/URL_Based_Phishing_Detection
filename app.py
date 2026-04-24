from flask import Flask, render_template, request, jsonify
import joblib
import pandas as pd
from features import extract_features

app = Flask(__name__)

# 1. Load model, feature order, AND the scaler
model = joblib.load('phishing_rf_model.pkl')
feature_names = joblib.load('feature_names.pkl')
scaler = joblib.load('scaler.pkl')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.json.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # 2. Extract features
    features_dict = extract_features(url)
    
    # 3. Convert to DataFrame to ensure correct column order
    features_df = pd.DataFrame([features_dict])[feature_names]
    
    # 4. APPLY THE SCALER
    features_scaled = scaler.transform(features_df)
    
    # 5. Predict using scaled features
    prediction = int(model.predict(features_scaled)[0])
    
    # 6. Probability Logic
    # Since 0 = Phishing, we look at the first index [0] of predict_proba
    probabilities = model.predict_proba(features_scaled)[0]
    phishing_prob = probabilities[1]  # Probability for Class 0 (Phishing)

    # 7. Response Logic (Aligned with 0 = Phishing)
    is_phishing = (prediction == 0)

    return jsonify({
        "url": url,
        "prediction": "Phishing" if is_phishing else "Safe",
        "is_phishing": is_phishing,
        "probability": f"{round(phishing_prob * 100, 2)}%",
        "features": features_dict
    })

if __name__ == '__main__':
    app.run(debug=True)