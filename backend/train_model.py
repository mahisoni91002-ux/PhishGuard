import pandas as pd
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report


# Load dataset
data = pd.read_csv("data/emails.csv")

X = data["text"]
y = data["label"]


# Convert email text into TF-IDF features
vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words="english",
    ngram_range=(1, 2)
)

X_tfidf = vectorizer.fit_transform(X)


# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X_tfidf,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)


# Train Naive Bayes model
model = MultinomialNB()
model.fit(X_train, y_train)


# Evaluate model
predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\nPhishGuard ML Model")
print("-------------------")
print(f"Accuracy: {accuracy:.2f}")
print("\nClassification Report:")
print(classification_report(y_test, predictions))


# Save model and vectorizer
joblib.dump(model, "phishing_model.joblib")
joblib.dump(vectorizer, "tfidf_vectorizer.joblib")

print("\nModel saved successfully!")
print("Created:")
print("- phishing_model.joblib")
print("- tfidf_vectorizer.joblib")