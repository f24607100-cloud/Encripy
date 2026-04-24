import pickle
import os

# Get absolute path to the current directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "svc_model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "tfidf_vectorizer.pkl")

_model = None
_tfidf = None

def _load_model():
    global _model, _tfidf
    if _model is None:
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
    if _tfidf is None:
        with open(VECTORIZER_PATH, "rb") as f:
            _tfidf = pickle.load(f)

def predict_spam(text):
    """
    Predicts if the given text is spam.
    Returns 1 if spam, 0 if normal.
    """
    try:
        _load_model()
        text_tfidf = _tfidf.transform([text])
        prediction = _model.predict(text_tfidf)
        with open("spam_debug.log", "a") as log:
            log.write(f"Input: {text}, Prediction: {prediction[0]}\n")
        return int(prediction[0])
    except Exception as e:
        with open("spam_debug.log", "a") as log:
            log.write(f"Error in predict_spam: {e}\n")
        print(f"Error in predict_spam: {e}")
        return 0

if __name__ == "__main__":
    user_text = input("Enter your text: ")
    print("Prediction:", predict_spam(user_text))