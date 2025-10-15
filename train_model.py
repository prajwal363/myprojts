import numpy as np
from sklearn.ensemble import RandomForestClassifier
import pickle

# Generate some example data
X = np.random.rand(100, 4)  # 100 samples, 4 features
y = np.random.randint(2, size=100)  # Binary target

# Train a RandomForestClassifier
model = RandomForestClassifier()
model.fit(X, y)

# Save the model to a file
with open("packet_classifier.pkl", "wb") as file:
    pickle.dump(model, file)

print("Model trained and saved as packet_classifier.pkl")