# 🔐 AI-Powered Phishing Detection System  
### (Machine Learning + Explainable AI + Flask + Tailwind)

A modern **AI-powered phishing detection web application** that detects malicious URLs in real time using **Machine Learning (XGBoost)**, **WHOIS intelligence**, and a **clean Tailwind CSS UI**.

The system follows a **hybrid approach**:
- Machine Learning for prediction
- Rule-based safeguards (trusted domains)
- Risk-based thresholds (Legitimate / Suspicious / Phishing)

---

## 🚀 Features

- ✅ Real-time phishing URL detection  
- 🤖 XGBoost-based ML model  
- 🌐 WHOIS domain age analysis  
- 🎯 Risk-based classification (Legitimate / Suspicious / Phishing)  
- 🎨 Modern UI using Tailwind CSS  
- 🔒 Trusted domain whitelisting  
- 📊 Confidence score visualization  

---

## 🧠 System Architecture

1. User enters a URL
2. URL features are extracted
3. WHOIS domain age is fetched
4. ML model predicts phishing probability
5. Risk thresholds classify the URL
6. Result is shown in UI with confidence

---

## 🖥️ User Interface Preview


::contentReference[oaicite:0]{index=0}


---

## 📁 Project Structure

```text
phishing_detection/
│
├── app.py
├── README.md
├── requirements.txt
├── data/
│   └── urls.csv
│
├── ml/
│   ├── feature_extractor.py
│   ├── train_model.py
│   ├── predict.py
│   └── __init__.py
│
├── whois_utils/
│   ├── whois_lookup.py
│   └── __init__.py
│
├── models/
│   └── xgboost_model.pkl
│
├── templates/
│   ├── index.html
│   └── result.html
│
├── static/
│
└── venv/
