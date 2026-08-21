from pathlib import Path
import joblib


BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_FILE = BASE_DIR / "ml" / "models" / "message_model.joblib"

model = joblib.load(MODEL_FILE)


test_messages = [
    "Hey, are you coming to college tomorrow?",
    
    "Congratulations! You have won a cash prize. Click the link now.",
    
    "Your bank KYC has expired. Verify your account immediately.",
    
    "URGENT! Your account will be blocked today. Send your OTP now.",
    
    "Please attend the meeting at 3 PM tomorrow.",
]


for message in test_messages:

    prediction = model.predict([message])[0]

    probabilities = model.predict_proba([message])[0]

    confidence = max(probabilities) * 100

    print("\n-----------------------------------")
    print("Message:")
    print(message)

    print("Prediction:", prediction)

    print(f"Confidence: {confidence:.2f}%")