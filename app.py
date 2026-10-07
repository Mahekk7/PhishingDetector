from flask import Flask, render_template, request, redirect, url_for
from pathlib import Path
import sqlite3
from datetime import datetime

import joblib
import pandas as pd
import cv2
import numpy as np

from models.url_features import extract_url_features


app = Flask(__name__)


# ============================================================
# PROJECT FOLDER
# ============================================================

BASE_DIR = Path(__file__).resolve().parent


# ============================================================
# LOAD TRAINED ML MODEL
# ============================================================

MODEL_PATH = BASE_DIR / "models" / "phishing_model.pkl"

model = joblib.load(MODEL_PATH)


# ============================================================
# MODEL FEATURES
# ============================================================

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


# ============================================================
# DATABASE
# ============================================================

DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DATABASE_PATH = DATA_DIR / "scan_history.db"


def init_database():

    connection = sqlite3.connect(DATABASE_PATH)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            result TEXT NOT NULL,
            risk_percentage REAL NOT NULL,
            scanned_at TEXT NOT NULL
        )
    """)

    cursor.execute("PRAGMA table_info(scan_history)")

    columns = [column[1] for column in cursor.fetchall()]

    if "scan_type" not in columns:

        cursor.execute("""
            ALTER TABLE scan_history
            ADD COLUMN scan_type TEXT DEFAULT 'URL'
        """)

    connection.commit()
    connection.close()


# ============================================================
# SAVE SCAN
# ============================================================

def save_scan(
    url,
    result,
    risk_percentage,
    scan_type="URL"
):

    connection = sqlite3.connect(DATABASE_PATH)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO scan_history
        (
            url,
            result,
            risk_percentage,
            scanned_at,
            scan_type
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        url,
        result,
        risk_percentage,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        scan_type
    ))

    connection.commit()
    connection.close()


# ============================================================
# GET SCAN HISTORY
# ============================================================

def get_scan_history():

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM scan_history
        ORDER BY id DESC
    """)

    history = cursor.fetchall()

    connection.close()

    return history


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_url_with_model(url):

    features = extract_url_features(url)

    input_data = pd.DataFrame(
        [[features[feature] for feature in MODEL_FEATURES]],
        columns=MODEL_FEATURES
    )

    prediction = model.predict(input_data)[0]

    probabilities = model.predict_proba(input_data)[0]

    phishing_probability = probabilities[1]

    risk_percentage = round(
        phishing_probability * 100,
        2
    )

    if prediction == 1:

        result = "Potentially Phishing"

    else:

        result = "Likely Safe"

    return result, risk_percentage, features


# ============================================================
# MESSAGE / SCAM ANALYSIS
# ============================================================

def analyze_message(message):

    message_lower = message.lower()

    risk_score = 0

    reasons = []


    # --------------------------------------------------------
    # URGENT / THREATENING LANGUAGE
    # --------------------------------------------------------

    urgent_words = [
        "urgent",
        "immediately",
        "act now",
        "act immediately",
        "within 24 hours",
        "within 48 hours",
        "account blocked",
        "account suspended",
        "account will be closed",
        "last warning",
        "final warning"
    ]

    for word in urgent_words:

        if word in message_lower:

            risk_score += 15

            reasons.append(
                f"Urgent or threatening language detected: '{word}'."
            )

            break


    # --------------------------------------------------------
    # OTP / VERIFICATION
    # --------------------------------------------------------

    otp_words = [
        "otp",
        "one time password",
        "one-time password",
        "verification code",
        "security code",
        "login code"
    ]

    for word in otp_words:

        if word in message_lower:

            risk_score += 20

            reasons.append(
                "Message mentions or requests an OTP/verification code."
            )

            break


    # --------------------------------------------------------
    # BANK / PAYMENT / MONEY
    # --------------------------------------------------------

    money_words = [
        "send money",
        "transfer money",
        "pay now",
        "payment",
        "upi",
        "bank account",
        "credit card",
        "debit card",
        "account number",
        "bank details",
        "refund",
        "transaction"
    ]

    for word in money_words:

        if word in message_lower:

            risk_score += 20

            reasons.append(
                "Financial or payment-related request detected."
            )

            break


    # --------------------------------------------------------
    # PRIZE / LOTTERY / REWARD
    # --------------------------------------------------------

    prize_words = [
        "you won",
        "you have won",
        "winner",
        "lottery",
        "prize",
        "cash reward",
        "free gift",
        "reward",
        "congratulations",
        "lucky winner"
    ]

    for word in prize_words:

        if word in message_lower:

            risk_score += 20

            reasons.append(
                "Prize, lottery or reward-related language detected."
            )

            break


    # --------------------------------------------------------
    # SUSPICIOUS LINK / CLICK REQUEST
    # --------------------------------------------------------

    link_words = [
        "click here",
        "click the link",
        "click this link",
        "verify now",
        "verify your account",
        "login now",
        "open this link",
        "visit this link",
        "http://",
        "https://",
        "www."
    ]

    for word in link_words:

        if word in message_lower:

            risk_score += 15

            reasons.append(
                "Message contains a link or asks the user to click/verify."
            )

            break


    # --------------------------------------------------------
    # SENSITIVE INFORMATION
    # --------------------------------------------------------

    personal_info_words = [
        "password",
        "pin",
        "cvv",
        "aadhaar",
        "aadhar",
        "pan card",
        "personal details",
        "identity proof",
        "id proof",
        "date of birth",
        "card details"
    ]

    for word in personal_info_words:

        if word in message_lower:

            risk_score += 20

            reasons.append(
                "Message requests sensitive personal or financial information."
            )

            break


    # --------------------------------------------------------
    # FREE MONEY / JOB / INVESTMENT
    # --------------------------------------------------------

    suspicious_offer_words = [
        "earn money",
        "make money",
        "work from home",
        "guaranteed income",
        "double your money",
        "investment opportunity",
        "guaranteed profit",
        "easy money",
        "instant money",
        "free money"
    ]

    for word in suspicious_offer_words:

        if word in message_lower:

            risk_score += 15

            reasons.append(
                "Suspicious money-making or investment offer detected."
            )

            break


    # --------------------------------------------------------
    # IMPERSONATION
    # --------------------------------------------------------

    impersonation_words = [
        "bank officer",
        "bank manager",
        "customer care",
        "support team",
        "income tax department",
        "police department",
        "government officer",
        "account manager"
    ]

    for word in impersonation_words:

        if word in message_lower:

            risk_score += 15

            reasons.append(
                "Message may be impersonating an organization or authority."
            )

            break


    # --------------------------------------------------------
    # LIMIT RISK TO 100
    # --------------------------------------------------------

    risk_score = min(risk_score, 100)


    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    if risk_score >= 60:

        result = "High Risk - Possible Scam"

        recommendation = (
            "Do not click links, share OTP/passwords, "
            "send money, or provide personal information."
        )

    elif risk_score >= 30:

        result = "Suspicious Message"

        recommendation = (
            "Verify the sender through an official source "
            "before clicking links or sharing information."
        )

    else:

        result = "Likely Safe"

        recommendation = (
            "No major scam-like patterns were detected. "
            "Still verify unexpected messages before taking action."
        )


    if not reasons:

        reasons.append(
            "No major scam-like patterns were detected."
        )


    return result, risk_score, reasons, recommendation


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ============================================================
# URL ANALYZER PAGE
# ============================================================

@app.route("/url-analyzer")
def url_analyzer():

    return render_template(
        "index.html"
    )


# ============================================================
# URL ANALYSIS
# ============================================================

@app.route(
    "/analyze-url",
    methods=["POST"]
)
def analyze_url():

    url = request.form.get(
        "url",
        ""
    ).strip()


    if not url:

        return render_template(
            "index.html",
            error="Please enter a URL."
        )


    try:

        result, risk_percentage, features = analyze_url_with_model(
            url
        )


        save_scan(
            url,
            result,
            risk_percentage,
            "URL"
        )


        return render_template(
            "index.html",
            analyzed_url=url,
            result=result,
            risk_percentage=risk_percentage,
            features=features
        )


    except Exception as error:

        return render_template(
            "index.html",
            error=f"Analysis error: {error}"
        )


# ============================================================
# QR SCANNER PAGE
# ============================================================

@app.route("/qr-scanner")
def qr_scanner():

    return render_template(
        "qr_scanner.html"
    )


# ============================================================
# QR CODE SCANNER
# ============================================================

@app.route(
    "/scan-qr",
    methods=["POST"]
)
def scan_qr():

    qr_image = request.files.get(
        "qr_image"
    )


    if not qr_image or qr_image.filename == "":

        return render_template(
            "qr_scanner.html",
            qr_error="Please select a QR code image."
        )


    try:

        image_bytes = qr_image.read()

        image_array = np.frombuffer(
            image_bytes,
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


        qr_detector = cv2.QRCodeDetector()

        decoded_data, points, _ = qr_detector.detectAndDecode(
            image
        )


        if not decoded_data:

            return render_template(
                "qr_scanner.html",
                qr_error=(
                    "No QR code or readable URL "
                    "was found in the image."
                )
            )


        extracted_url = decoded_data.strip()


        result, risk_percentage, features = analyze_url_with_model(
            extracted_url
        )


        save_scan(
            extracted_url,
            result,
            risk_percentage,
            "QR"
        )


        return render_template(
            "qr_scanner.html",
            qr_success="QR code scanned successfully!",
            qr_url=extracted_url,
            qr_result=result,
            qr_risk_percentage=risk_percentage,
            qr_features=features
        )


    except Exception as error:

        return render_template(
            "qr_scanner.html",
            qr_error=f"QR analysis error: {error}"
        )


# ============================================================
# MESSAGE DETECTOR PAGE
# ============================================================

@app.route("/message-detector")
def message_detector():

    return render_template(
        "message_detector.html"
    )


# ============================================================
# MESSAGE / SCAM DETECTION
# ============================================================

@app.route(
    "/analyze-message",
    methods=["POST"]
)
def analyze_message_route():

    message = request.form.get(
        "message",
        ""
    ).strip()


    if not message:

        return render_template(
            "message_detector.html",
            message_error="Please enter a message or email."
        )


    try:

        result, risk_percentage, reasons, recommendation = analyze_message(
            message
        )


        save_scan(
            message,
            result,
            risk_percentage,
            "Message"
        )


        return render_template(
            "message_detector.html",
            analyzed_message=message,
            message_result=result,
            message_risk_percentage=risk_percentage,
            message_reasons=reasons,
            message_recommendation=recommendation
        )


    except Exception as error:

        return render_template(
            "message_detector.html",
            message_error=f"Message analysis error: {error}"
        )


# ============================================================
# CYBER SAFETY TIPS
# ============================================================

@app.route("/safety-tips")
def safety_tips():

    return render_template(
        "safety_tips.html"
    )


# ============================================================
# CYBER SAFETY QUIZ
# ============================================================

@app.route("/quiz")
def quiz():

    return render_template(
        "quiz.html"
    )


# ============================================================
# PROJECT FEATURES
# ============================================================

@app.route("/features")
def features():

    return render_template(
        "features.html"
    )


# ============================================================
# SCAN HISTORY
# ============================================================

@app.route("/history")
def history():

    scan_history = get_scan_history()

    return render_template(
        "history.html",
        history=scan_history
    )


# ============================================================
# CLEAR HISTORY
# ============================================================

@app.route(
    "/clear-history",
    methods=["POST"]
)
def clear_history():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()

    cursor.execute(
        "DELETE FROM scan_history"
    )

    connection.commit()

    connection.close()

    return redirect(
        url_for("history")
    )


# ============================================================
# INITIALIZE DATABASE
# ============================================================

init_database()


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )