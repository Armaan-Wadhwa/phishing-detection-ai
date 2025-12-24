# 🛡️ AI-Based Phishing Detection System

An end-to-end phishing domain detection pipeline using OSINT techniques and Machine Learning.

## 🚀 Features
- Automated domain discovery using OSINT
- WHOIS & DNS enrichment
- ML-based phishing classification
- Evidence collection via screenshots
- Interactive Streamlit dashboard
- PostgreSQL backend

## 🧱 Architecture
User Input → Crawlers → Enrichment → ML → Evidence → Dashboard

## 🛠️ Tech Stack
- Python, Scikit-learn
- PostgreSQL
- Streamlit
- Playwright
- OSINT Crawlers

## ▶️ How to Run
```bash
python main.py init-db
python main.py scan --name "HDFC Bank" --domain hdfcbank.com --keywords hdfc,login
streamlit run app.py
