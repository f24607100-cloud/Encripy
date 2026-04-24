import os
import torch
import torch.nn as nn
from torchvision import transforms, models
from PIL import Image

# -----------------------------
# Config
# -----------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(SCRIPT_DIR, "binary_image_classifier.pth")
IMG_SIZE = 224
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

CLASS_NAMES = ["NaturalImages", "SpamImages"]

# -----------------------------
# Image Transform (same as training)
# -----------------------------
transform = transforms.Compose([
    transforms.Resize((IMG_SIZE, IMG_SIZE)),
    transforms.ToTensor(),
    transforms.Normalize(
        mean=[0.485, 0.456, 0.406],
        std=[0.229, 0.224, 0.225]
    )
])

# -----------------------------
# Global Model (lazy loading)
# -----------------------------
_model = None

def _load_model():
    """Load the model once and cache it."""
    global _model
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"Model file not found: {MODEL_PATH}")
        
        _model = models.resnet18(pretrained=False)
        _model.fc = nn.Linear(_model.fc.in_features, 2)
        _model.load_state_dict(torch.load(MODEL_PATH, map_location=DEVICE))
        _model = _model.to(DEVICE)
        _model.eval()

# -----------------------------
# Inference Function
# -----------------------------
def predict_spam_image(image_path):
    """
    Predicts if the given image is spam.
    
    Args:
        image_path (str): Path to the image file
        
    Returns:
        int: 1 if spam, 0 if normal
    """
    try:
        _load_model()
        
        image = Image.open(image_path).convert("RGB")
        image = transform(image).unsqueeze(0).to(DEVICE)

        with torch.no_grad():
            outputs = _model(image)
            probs = torch.softmax(outputs, dim=1)
            confidence, predicted = torch.max(probs, 1)

        return int(predicted.item())
    except Exception as e:
        print(f"Error in spam image prediction: {e}")
        return 0  # Default to not spam on error

# -----------------------------
# Main (for testing)
# -----------------------------
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        test_image = sys.argv[1]
    else:
        test_image = "test.jpg"
    
    if os.path.exists(test_image):
        result = predict_spam_image(test_image)
        label = CLASS_NAMES[result]
        print(f"Image: {test_image}")
        print(f"Prediction: {label} ({result})")
    else:
        print(f"Test image not found: {test_image}")
