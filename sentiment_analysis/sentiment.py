import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch.nn.functional as F

import os

# 1️⃣ Force CPU
device = torch.device("cpu")

# 2️⃣ Path to your saved model folder
# Use absolute path relative to this script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = BASE_DIR

# 3️⃣ Load tokenizer & model
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)

model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_PATH,
    torch_dtype=torch.float32,   # CPU-safe
)

model.to(device)
model.eval()

# 4️⃣ Label mapping
id2sentiment = {
    0: "negative",
    1: "neutral",
    2: "positive"
}

# 5️⃣ Prediction function
def predict_sentiment(text: str):
    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        padding=True,
        max_length=128
    )

    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():
        outputs = model(**inputs)

    probs = F.softmax(outputs.logits, dim=1)[0]
    pred_id = torch.argmax(probs).item()

    return {
        "text": text,
        "sentiment": id2sentiment[pred_id],
        "confidence": round(probs[pred_id].item(), 4),
        "probabilities": {
            id2sentiment[i]: round(probs[i].item(), 4)
            for i in range(len(probs))
        }
    }

# 6️⃣ Test
if __name__ == "__main__":
    sentence = "Any plans of allowing sub tasks to show up in the widget?"
    result = predict_sentiment(sentence)
    print(result)
