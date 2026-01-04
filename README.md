# AI-NIDS-Project
# 🛡️ AI-Based Network Intrusion Detection System (NIDS)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-App-red)
![Machine Learning](https://img.shields.io/badge/Model-Random%20Forest-green)

## 📌 Project Overview
This project is an **AI-powered Network Intrusion Detection System (NIDS)** designed to detect malicious network traffic in real-time. It leverages **Machine Learning (Random Forest Classifier)** to analyze network packet data and classify it as either **"Normal"** or **"Malicious" (DDoS Attack)**.

The system is built using **Python** and **Streamlit** for the interactive dashboard, and it trains on the real-world **CIC-IDS2017** cybersecurity dataset.

## ✨ Features
* **Production-Ready Analysis:** Uses real network traffic data (CIC-IDS2017) instead of random simulations.
* **Machine Learning Model:** Trains a Random Forest Classifier with **99%+ accuracy** on DDoS attack patterns.
* **Interactive Dashboard:** User-friendly interface to view historical data, train models, and simulate traffic.
* **Real-Time Simulation:** Input custom packet parameters (Packet Size, Duration, Port, etc.) to test the model's detection capabilities instantly.

## 🛠️ Technologies Used
* **Language:** Python
* **GUI Framework:** Streamlit
* **Data Processing:** Pandas, NumPy
* **Machine Learning:** Scikit-learn (Random Forest)
* **Visualization:** Streamlit Charts

---

## 🚀 How to Run Locally

### 1. Prerequisites
Ensure you have **Python 3.8+** installed. You can verify this by running:
```bash
python --version

### 2. Clone the Repository
git clone [https://github.com/your-username/AI-Network-IDS.git](https://github.com/your-username/AI-Network-IDS.git)
cd AI-Network-IDS
