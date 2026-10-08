from flask import Flask, render_template, request, redirect, url_for
from pathlib import Path
import sqlite3
from datetime import datetime
import joblib
import pandas as pd
import cv2

from models.url_features import extract_url_features


# --------------------------------------------------
# FLASK APP
# --------------------------------------------------

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent


# --------------------------------------------------
# MODEL
# --------------------------------------------------

MODEL_PATH = BASE_DIR / "models" / "phishing_model.pkl"

model = joblib.load(MODEL_PATH)


MODEL_FEATURES = [
    "URL_Length",
    "having_At_Symbol",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "having_IP_Address",
    "Shortining_Service",
    "HTTPS_token"
]


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

# Vercel allows temporary writing only inside /tmp
DATA_DIR = Path("/tmp")

DB_PATH = DATA_DIR / "scan_history.db"


def init_database():
    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            result TEXT,
            risk_percentage INTEGER,
            scan_type TEXT,
            scanned_at TEXT
        )
    """)

    # Add scan_type column if an older database exists
    try:
        cursor.execute(
            "ALTER TABLE scan_history ADD COLUMN scan_type TEXT DEFAULT 'URL'"
        )
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()


def save_scan(url, result, risk_percentage, scan_type="URL"):
    try:
        conn = sqlite3.connect(DB_PATH)

        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO scan_history
            (url, result, risk_percentage, scan_type, scanned_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            url,
            result,
            risk_percentage,
            scan_type,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

        conn.commit()
        conn.close()

    except Exception as e:
        print("Database save error:", e)


def get_scan_history():
    try:
        conn = sqlite3.connect(DB_PATH)

        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, url, result, risk_percentage, scan_type, scanned_at
            FROM scan_history
            ORDER BY id DESC
        """)

        history = cursor.fetchall()

        conn.close()

        return history

    except Exception as e:
        print("Database history error:", e)
        return []


# --------------------------------------------------
# URL ANALYSIS
# --------------------------------------------------

def analyze_url_with_model(url):

    features = extract_url_features(url)

    feature_values = {
        feature: features.get(feature, 0)
        for feature in MODEL_FEATURES
    }

    df = pd.DataFrame(
        [feature_values],
        columns=MODEL_FEATURES
    )

    prediction = model.predict(df)[0]

    # Get probability if model supports predict_proba
    try:
        probabilities = model.predict_proba(df)[0]

        # Assuming class 1 represents phishing
        if hasattr(model, "classes_") and 1 in model.classes_:
            phishing_index = list(model.classes_).index(1)
            phishing_probability = probabilities[phishing_index]
        else:
            phishing_probability = probabilities[-1]

        risk_percentage = int(phishing_probability * 100)

    except Exception:
        risk_percentage = 100 if prediction == 1 else 0

    # Result
    if prediction == 1:
        result = "Phishing / Malicious URL"
    else:
        result = "Safe / Legitimate URL"

    return result, risk_percentage, feature_values


# --------------------------------------------------
# MESSAGE ANALYSIS
# --------------------------------------------------

def analyze_message(message):

    message_lower = message.lower()

    risk = 0
    reasons = []

    # Urgency
    urgency_words = [
        "urgent",
        "immediately",
        "act now",
        "hurry",
        "within 24 hours",
        "account will be blocked",
        "last warning"
    ]

    for word in urgency_words:
        if word in message_lower:
            risk += 15
            reasons.append("Uses urgent or threatening language.")
            break

    # OTP
    otp_words = [
        "otp",
        "one time password",
        "verification code",
        "security code"
    ]

    for word in otp_words:
        if word in message_lower:
            risk += 20
            reasons.append("Requests or mentions an OTP/security code.")
            break

    # Money / payment
    payment_words = [
        "payment",
        "pay now",
        "transfer money",
        "bank account",
        "credit card",
        "debit card",
        "upi",
        "transaction"
    ]

    for word in payment_words:
        if word in message_lower:
            risk += 15
            reasons.append("Contains financial or payment-related content.")
            break

    # Prize / lottery
    prize_words = [
        "winner",
        "won",
        "lottery",
        "prize",
        "reward",
        "cashback",
        "free gift"
    ]

    for word in prize_words:
        if word in message_lower:
            risk += 20
            reasons.append("Contains suspicious prize, reward or lottery claims.")
            break

    # Links
    if "http://" in message_lower or "https://" in message_lower or "www." in message_lower:
        risk += 15
        reasons.append("Contains an external link.")

    # Sensitive information
    sensitive_words = [
        "password",
        "pin",
        "cvv",
        "card number",
        "aadhaar",
        "pan number"
    ]

    for word in sensitive_words:
        if word in message_lower:
            risk += 20
            reasons.append("Requests sensitive personal or financial information.")
            break

    # Investment / job scams
    scam_words = [
        "investment",
        "double your money",
        "guaranteed return",
        "work from home",
        "earn money",
        "job offer",
        "registration fee"
    ]

    for word in scam_words:
        if word in message_lower:
            risk += 15
            reasons.append("Contains common investment, job or money-making scam patterns.")
            break

    # Impersonation
    impersonation_words = [
        "bank",
        "police",
        "government",
        "income tax",
        "customs",
        "courier",
        "support team"
    ]

    for word in impersonation_words:
        if word in message_lower:
            risk += 10
            reasons.append("May involve impersonation of an organisation or authority.")
            break

    # Limit risk to 100
    risk = min(risk, 100)

    # Final result
    if risk >= 60:
        result = "High Risk - Possible Scam"

    elif risk >= 30:
        result = "Suspicious Message"

    else:
        result = "Likely Safe"

    if not reasons:
        reasons.append("No major scam indicators were detected.")

    if risk >= 60:
        recommendation = (
            "Do not click links, share OTPs or provide personal information. "
            "Verify the sender through an official source."
        )

    elif risk >= 30:
        recommendation = (
            "Be careful and verify the message before taking any action."
        )

    else:
        recommendation = (
            "The message appears relatively safe, but always verify unexpected requests."
        )

    return result, risk, reasons, recommendation


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# --------------------------------------------------
# URL ANALYZER PAGE
# --------------------------------------------------

@app.route("/url-analyzer")
def url_analyzer():
    return render_template("index.html")


# --------------------------------------------------
# ANALYZE URL
# --------------------------------------------------

@app.route("/analyze-url", methods=["POST"])
def analyze_url():

    url = request.form.get("url", "").strip()

    if not url:
        return render_template(
            "index.html",
            error="Please enter a URL."
        )

    try:

        result, risk_percentage, features = analyze_url_with_model(url)

        save_scan(
            url,
            result,
            risk_percentage,
            "URL"
        )

        return render_template(
            "index.html",
            result=result,
            analyzed_url=url,
            risk_percentage=risk_percentage,
            features=features
        )

    except Exception as e:

        print("URL analysis error:", e)

        return render_template(
            "index.html",
            error="Unable to analyze this URL. Please try again."
        )


# --------------------------------------------------
# QR SCANNER PAGE
# --------------------------------------------------

@app.route("/qr-scanner")
def qr_scanner():
    return render_template("qr_scanner.html")


# --------------------------------------------------
# QR SCANNER
# --------------------------------------------------

@app.route("/scan-qr", methods=["POST"])
def scan_qr():

    file = request.files.get("qr_image")

    if not file:
        return render_template(
            "qr_scanner.html",
            qr_error="Please upload a QR code image."
        )

    try:

        # Read uploaded image
        file_bytes = file.read()

        import numpy as np

        image_array = np.frombuffer(
            file_bytes,
            np.uint8
        )

        image = cv2.imdecode(
            image_array,
            cv2.IMREAD_COLOR
        )

        if image is None:
            return render_template(
                "qr_scanner.html",
                qr_error="Unable to read the uploaded image."
            )

        # Detect QR
        detector = cv2.QRCodeDetector()

        decoded_text, points, _ = detector.detectAndDecode(image)

        if not decoded_text:

            return render_template(
                "qr_scanner.html",
                qr_error="No QR code could be detected in the image."
            )

        qr_url = decoded_text.strip()

        # Analyze decoded URL
        result, risk_percentage, features = analyze_url_with_model(qr_url)

        save_scan(
            qr_url,
            result,
            risk_percentage,
            "QR"
        )

        return render_template(
            "qr_scanner.html",
            qr_success="QR code scanned successfully.",
            qr_url=qr_url,
            qr_result=result,
            qr_risk_percentage=risk_percentage,
            qr_features=features
        )

    except Exception as e:

        print("QR scanning error:", e)

        return render_template(
            "qr_scanner.html",
            qr_error="Unable to scan this QR code. Please try another image."
        )


# --------------------------------------------------
# MESSAGE DETECTOR PAGE
# --------------------------------------------------

@app.route("/message-detector")
def message_detector():
    return render_template("message_detector.html")


# --------------------------------------------------
# ANALYZE MESSAGE
# --------------------------------------------------

@app.route("/analyze-message", methods=["POST"])
def analyze_message_route():

    message = request.form.get("message", "").strip()

    if not message:

        return render_template(
            "message_detector.html",
            message_error="Please enter a message."
        )

    try:

        (
            message_result,
            message_risk_percentage,
            message_reasons,
            message_recommendation
        ) = analyze_message(message)

        save_scan(
            message[:200],
            message_result,
            message_risk_percentage,
            "MESSAGE"
        )

        return render_template(
            "message_detector.html",
            analyzed_message=message,
            message_result=message_result,
            message_risk_percentage=message_risk_percentage,
            message_reasons=message_reasons,
            message_recommendation=message_recommendation
        )

    except Exception as e:

        print("Message analysis error:", e)

        return render_template(
            "message_detector.html",
            message_error="Unable to analyze this message."
        )


# --------------------------------------------------
# SAFETY TIPS
# --------------------------------------------------

@app.route("/safety-tips")
def safety_tips():
    return render_template("safety_tips.html")


# --------------------------------------------------
# QUIZ
# --------------------------------------------------

@app.route("/quiz")
def quiz():
    return render_template("quiz.html")


# --------------------------------------------------
# FEATURES
# --------------------------------------------------

@app.route("/features")
def features():
    return render_template("features.html")


# --------------------------------------------------
# HISTORY
# --------------------------------------------------

@app.route("/history")
def history():

    scan_history = get_scan_history()

    return render_template(
        "history.html",
        history=scan_history
    )


# --------------------------------------------------
# CLEAR HISTORY
# --------------------------------------------------

@app.route("/clear-history", methods=["POST"])
def clear_history():

    try:

        conn = sqlite3.connect(DB_PATH)

        cursor = conn.cursor()

        cursor.execute("DELETE FROM scan_history")

        conn.commit()
        conn.close()

    except Exception as e:

        print("Clear history error:", e)

    return redirect(url_for("history"))


# --------------------------------------------------
# INITIALIZE DATABASE
# --------------------------------------------------

init_database()


# --------------------------------------------------
# LOCAL DEVELOPMENT
# --------------------------------------------------

if __name__ == "__main__":
    app.run(
        debug=True
    )