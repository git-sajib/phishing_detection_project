# Explainable Machine Learning–Based Phishing Website Detection

AI-powered phishing detection using URL & HTML features with explainable machine learning.

---

## 🚀 Features

✔ phishing detection  
✔ explainable AI (SHAP)  
✔ URL & HTML feature analysis  
✔ Flask API backend  
✔ React frontend  
✔ real dataset   


---

## 🏗 Project Structure

```
phishing_detection_project/
│
├── backend/
│   ├── app.py
│   ├── src/
│   │   ├── data_preprocessing.py
│   │   ├── feature_extraction.py
│   │   ├── model_training.py
│   │   └── explainability.py
│   └── models/
│
├── frontend/  
│
├── data/
│   ├── phishing_large.csv
│
└── README.md
```

---

## ⚙ Installation

### 1️⃣ Clone Repository

```sh
git clone https://github.com/your-username/phishing-detection.git
cd phishing-detection
```

---

### 2️⃣ Backend Setup

Create virtual environment:

```sh
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

Install dependencies:

```sh
pip install -r requirements.txt
```

Run API:

```sh
python backend/app.py
```

---

### 3️⃣ Frontend Setup

```sh
cd frontend
npm install
npm run dev
```

---

## 🧠 Training Pipeline

### Dataset Collection

Real data from:

✔ Kaggle
✔ legitimate URLs  
✔ synthetic samples

Run crawler:

```sh
python crawler/phishtank_crawler.py
python crawler/legit_generator.py
python crawler/dataset_generator.py
```

---

### Preprocessing

```sh
python backend/src/data_preprocessing.py
```

Removes:

✔ duplicates  
✔ missing values  
✔ label issues

---

### Feature Engineering

Extracts:

✔ URL length  
✔ digits  
✔ special characters  
✔ domain info  
✔ HTML elements

### Model Training

Machine learning pipeline:

✔ XGBoost  
✔ StandardScaler  
✔ GridSearch optimization

Train:

```sh
python backend/src/model_training.py
```

Output:

```
models/phishing_model.pkl
models/scaler.pkl
```

---

## 🌐 API Usage

Endpoint:

```
POST /predict
```

Request:

```json
{
  "url": "https://example.com"
}
```

Response:

```json
{
  "result": "Legitimate",
  "legitimate_percentage": 92.5,
  "shap": {
    "features": ["url_length", "num_forms"],
    "importance": [0.45, 0.25]
  }
}
```

---

## 📊 Evaluation

Metrics:

✔ accuracy  
✔ F1 score  
✔ classification report  
✔ SHAP explainability

Example:

```
Accuracy: 96.5%
F1 Score: 0.94
```

---

## 🛡 Security & Explainability

✔ phishing detection  
✔ feature importance  
✔ model transparency  
✔ cybersecurity research

---

## 🚀 Deployment

Backend:

```sh
python backend/app.py
```

Frontend:

```sh
npm run build
```

---

## 💡 Future Improvements

✔ larger dataset  
✔ deep learning  
✔ real-time crawler  
✔ advanced explainability  
✔ security enhancements

---

## 🤝 Contributing

Pull requests welcome.

1. fork repository  
2. create feature branch  
3. commit changes  
4. submit PR

---

## 📄 License

MIT License

---

## 👨‍💻 Author

Samiul Islam  
Full-Stack & ML Developer
