from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import uvicorn
from fastapi.middleware.cors import CORSMiddleware
from vt_util import check_url_virustotal  # ✅ Import the VT checker

app = FastAPI()

origins = ["*"]  # Update this for production

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["POST"],
    allow_headers=["*"],
)

# Load model and vectorizer
model = joblib.load("Url_phishing.pkl")
vectorizer = joblib.load("url_VECtorizer.pkl")

# Define input data schema
class UrlInput(BaseModel):
    url: str

@app.post("/predict")
def predict_phishing(data: UrlInput):
    url = data.url
    try:
        # Model prediction
        url_vector = vectorizer.transform([url])
        pred = model.predict(url_vector)[0]
        label = "phishing" if pred == 1 else "legit"

        # VirusTotal result
        vt_result = check_url_virustotal(url)

        # Combine both
        return {
            "prediction": label,
            "virustotal": vt_result
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
