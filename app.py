import pandas as pd
import re
import streamlit as st
import os
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.multiclass import OneVsRestClassifier
from sklearn.svm import LinearSVC
from sklearn.metrics import accuracy_score, f1_score



acc = None
f1 = None



def clean_text(text):
    text = str(text).lower()
    text = re.sub(r'http\S+', ' URL ', text)
    text = re.sub(r'\d+\.\d+\.\d+\.\d+', ' IP ', text)
    text = re.sub(r'[a-f0-9]{32,64}', ' HASH ', text)
    text = re.sub(r'[^a-zA-Z0-9 ]', ' ', text)
    return text



def detect_patterns(text):
    patterns = []

    if re.search(r'http\S+', text):
        patterns.append("URL")

    if re.search(r'\d+\.\d+\.\d+\.\d+', text):
        patterns.append("IP Address")

    if re.search(r'[a-f0-9]{32,64}', text.lower()):
        patterns.append("Hash Value")

    if re.search(r'\\', text):
        patterns.append("File Path")

    return patterns



def calculate_risk(text, labels, patterns):
    score = 0
    text_lower = text.lower()

    
    score += len(labels) * 2
    score += len(patterns) * 2

    
    high_risk_keywords = ["attack", "ddos", "breach", "exploit", "malware", "ransomware"]
    for word in high_risk_keywords:
        if word in text_lower:
            score += 3

    
    ip_matches = re.findall(r'\d+\.\d+\.\d+\.\d+', text)
    if len(ip_matches) >= 2:
        score += 4

    
    if "target" in text_lower or "server" in text_lower:
        score += 2

    
    if "MALWARE" in labels:
        score += 4
    if "THREAT-ACTOR" in labels:
        score += 3

    return min(score, 10)



def generate_explanation(text, labels, patterns):
    reasons = []
    text_lower = text.lower()

    if "malware" in text_lower:
        reasons.append("Contains malware-related keywords")

    if "system32" in text_lower:
        reasons.append("Sensitive system directory referenced")

    if "attack" in text_lower:
        reasons.append("Attack-related activity detected")

    ip_matches = re.findall(r'\d+\.\d+\.\d+\.\d+', text)
    if len(ip_matches) >= 2:
        reasons.append("Multiple IPs indicate possible distributed attack (DDoS)")

    if patterns:
        reasons.append("Suspicious patterns detected")

    if not reasons:
        reasons.append("General anomaly detected")

    return reasons



if os.path.exists("model.pkl"):
    model = joblib.load("model.pkl")
    vectorizer = joblib.load("vectorizer.pkl")
    mlb = joblib.load("mlb.pkl")

    if os.path.exists("accuracy.pkl"):
        acc = joblib.load("accuracy.pkl")

    if os.path.exists("f1.pkl"):
        f1 = joblib.load("f1.pkl")

else:
    df = pd.read_csv("cyber-threat-intelligence_all.csv")
    df = df.dropna(subset=['text', 'label'])

    df['label'] = df['label'].astype(str).str.upper().str.strip()
    df = df[df['label'] != 'NAN']

    df['label'] = df['label'].apply(lambda x: [x])
    df['clean_text'] = df['text'].apply(clean_text)

    vectorizer = TfidfVectorizer(max_features=10000, ngram_range=(1,2), stop_words='english')
    X = vectorizer.fit_transform(df['clean_text'])

    mlb = MultiLabelBinarizer()
    y = mlb.fit_transform(df['label'])

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    model = OneVsRestClassifier(LinearSVC(class_weight='balanced'))
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average='micro')

    joblib.dump(model, "model.pkl")
    joblib.dump(vectorizer, "vectorizer.pkl")
    joblib.dump(mlb, "mlb.pkl")
    joblib.dump(acc, "accuracy.pkl")
    joblib.dump(f1, "f1.pkl")


def predict_threat(text):
    cleaned = clean_text(text)
    vec = vectorizer.transform([cleaned])
    pred = model.predict(vec)
    labels = mlb.inverse_transform(pred)
    return labels[0] if labels else []



def get_confidence(text, labels, patterns, risk):
    vec = vectorizer.transform([clean_text(text)])

    try:
        scores = model.decision_function(vec)
        model_conf = abs(scores).max()
        model_conf = min(1, model_conf / 2)
    except:
        model_conf = 0.5

    confidence = (
        model_conf * 50 +
        (risk / 10) * 30 +
        (len(patterns) * 5) +
        (len(labels) * 5)
    )

    confidence = max(30, min(100, confidence))
    return round(confidence, 2)



st.set_page_config(page_title="Cyber Threat Analyzer", layout="wide", page_icon="🔐")

st.markdown("""
<style>
body { background-color: #0e1117; }
.stTextArea textarea {
    background-color: #1e1e2f;
    color: white;
    border-radius: 10px;
}
.stButton button {
    background: linear-gradient(90deg, #ff4b4b, #ff6b6b);
    color: white;
    border-radius: 10px;
    height: 50px;
    width: 220px;
    font-size: 18px;
}
</style>
""", unsafe_allow_html=True)

st.markdown("<h1 style='text-align:center;color:#ff4b4b;'>🔐 AI Cyber Threat Analyzer</h1>", unsafe_allow_html=True)
st.caption("⚡ AI + Pattern-based Hybrid Threat Detection System")

st.markdown("---")

user_input = st.text_area("📝 Paste logs / suspicious text:")

if st.button("🚀 Analyze Threat"):
    if user_input.strip():

        labels = predict_threat(user_input)
        patterns = detect_patterns(user_input)
        risk = calculate_risk(user_input, labels, patterns)
        explanation = generate_explanation(user_input, labels, patterns)
        confidence = get_confidence(user_input, labels, patterns, risk)

        # Metrics
        col1, col2, col3 = st.columns(3)

        if acc:
            col1.metric("📊 Accuracy", f"{acc:.2f}")
        if f1:
            col2.metric("🎯 F1 Score", f"{f1:.2f}")

        col3.metric("🧠 Confidence", f"{confidence}%")

        st.markdown("## 🧠 Analysis Result")

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### 🔎 Threat Indicators")
            if labels:
                for l in labels:
                    st.error(l)
            else:
                st.success("No major threats detected")

        with col2:
            st.markdown("### 📡 Detected Patterns")
            if patterns:
                for p in patterns:
                    st.warning(p)
            else:
                st.success("No suspicious patterns")

        st.markdown("### ⚠️ Risk Assessment")
        st.progress(risk / 10)

        if risk >= 6:
            st.error(f"🔥 HIGH RISK ({risk:.1f}/10)")
        elif risk >= 3:
            st.warning(f"⚠️ MEDIUM RISK ({risk:.1f}/10)")
        else:
            st.success(f"✅ LOW RISK ({risk:.1f}/10)")

        st.markdown("### 💡 AI Explanation")
        for e in explanation:
            st.write(f"• {e}")

    else:
        st.warning("Please enter text")