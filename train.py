import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler  # Added for scaling

# 1. Load Dataset
df = pd.read_csv('dataset.csv')

# 2. Data Cleaning
df.dropna(subset=['ClassLabel'], inplace=True)
df['ClassLabel'] = df['ClassLabel'].astype(int)

# 3. Separate Features and Target
X = df.drop(['URL', 'ClassLabel'], axis=1)
y = df['ClassLabel']

# 4. Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 5. Apply Scaling
scaler = StandardScaler()

# fit_transform learns the mean/std from training data and scales it
X_train_scaled = scaler.fit_transform(X_train)

# transform uses the same mean/std to scale the test data
X_test_scaled = scaler.transform(X_test)

# 6. Train the model on the SCALED data
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train_scaled, y_train)

# 7. Save the Model, the Scaler, and Feature Names
joblib.dump(model, 'phishing_rf_model.pkl')
joblib.dump(scaler, 'scaler.pkl')  # CRITICAL: Save the scaler for app.py
joblib.dump(X.columns.tolist(), 'feature_names.pkl')

print(f"Model and Scaler trained successfully! Processed {len(df)} rows.")