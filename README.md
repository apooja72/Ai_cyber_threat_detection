# 🚀 AI Cyber Threat Detection System

## 📌 Overview
An AI-based Cyber Threat Detection System that analyzes textual data such as system logs, alerts, and messages to identify potential cyber threats. The system uses Natural Language Processing (NLP) and Machine Learning to classify threats like phishing, malware, or safe activity, along with risk scoring and explainable outputs.

---

## 🎯 Problem Statement
Cybersecurity teams handle large volumes of text-based data, including logs and alerts. Manual analysis is time-consuming, inefficient, and prone to human error. There is a need for an automated system that can quickly analyze this data and detect potential cyber threats.

---

## 🎯 Objectives
- Automate cyber threat detection from textual data  
- Reduce manual effort and human error  
- Classify text into phishing, malware, or safe activity  
- Provide real-time threat detection  
- Generate risk scores with explanations  
- Build a user-friendly interface for easy interaction  

---

## 💡 Proposed Solution
We developed an AI-based system that uses NLP techniques to process and analyze text data. The system:
- Cleans and preprocesses input text  
- Converts text into numerical features using TF-IDF  
- Uses machine learning to classify threats  
- Detects patterns like IPs, URLs, and file paths  
- Provides risk scores and explanations  

---

## 🏗️ System Architecture

### 🔹 Workflow
1. **User Interface (Streamlit)**  
   - Accepts input (logs, alerts, messages)  
   - Displays results clearly  

2. **Preprocessing Module**  
   - Cleans text using regex  
   - Normalizes URLs, IPs, hashes  

3. **Feature Extraction**  
   - Converts text into vectors using TF-IDF  

4. **Machine Learning Model**  
   - OneVsRestClassifier + LinearSVC  
   - Classifies threats (phishing, malware, safe)  

5. **Pattern Detection Module**  
   - Detects IPs, URLs, file paths, hashes  

6. **Hybrid Decision Engine**  
   - Combines ML + rule-based outputs  

7. **Risk Scoring Module**  
   - Assigns score (0–10) based on severity  

8. **Explanation Module**  
   - Provides human-readable reasoning  

---

## ⚙️ Tech Stack
- **Programming Language:** Python  
- **Libraries:** pandas, scikit-learn, re, joblib  
- **ML Techniques:** TF-IDF, LinearSVC, Multi-label classification  
- **Frontend:** Streamlit  
- **Dataset:** Cyber Threat Dataset (Network, Text & Relation)  
- **Approach:** Hybrid (Machine Learning + Rule-based)  

---

## 🔍 Features
- ✅ Threat Classification (Phishing, Malware, Safe)  
- ✅ Pattern Detection (IP, URL, Hash, File Path)  
- ✅ Hybrid Detection System  
- ✅ Risk Scoring (0–10)  
- ✅ Explainable AI Output  
- ✅ Performance Metrics (Accuracy, F1 Score)  
- ✅ Interactive Streamlit UI  

---

## ⚙️ Implementation Details

### 1. Data Preprocessing
- Clean text using regex  
- Remove noise and unwanted characters  
- Normalize patterns (IP, URL, hashes)  

### 2. Feature Engineering
- TF-IDF (1-gram & 2-gram)  

### 3. Model Development
- OneVsRestClassifier + LinearSVC  
- Multi-label classification  

### 4. Training
- 80% training, 20% testing  

### 5. Evaluation
- Accuracy  
- F1 Score  

### 6. Hybrid Logic
- Combines ML predictions + rule-based detection  

### 7. Output Generation
- Displays indicators, patterns  
- Assigns risk score  
- Provides explanation  

---

## 📊 Usability
- Simple and easy-to-use interface  
- Fast real-time processing  
- Clear and understandable outputs  

---

## 🌍 Impact
- Reduces manual analysis effort  
- Improves threat detection speed  
- Supports cybersecurity teams  
- Enhances decision-making with explanations  

---

## 🚀 Future Improvements
- Use BERT / Deep Learning models  
- Real-time log monitoring  
- SIEM tool integration  
- Analytics dashboard  
- API / enterprise deployment  
- Improved dataset quality  


## 🔗 GitHub Repository
👉 https://github.com/apooja72/Ai_cyber_threat_detection  


## 📌 Conclusion
This project presents an intelligent AI-based system for detecting cyber threats from textual data. By combining machine learning with rule-based detection, it ensures accurate classification, risk scoring, and explainability. The system improves efficiency, reduces manual effort, and enables faster cybersecurity decision-making.
