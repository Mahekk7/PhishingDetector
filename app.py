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



# ===== URL rule checks (built into app.py) =====
import re
from urllib.parse import urlparse

import re
from urllib.parse import urlparse

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "rebrand.ly",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work",
    "support", "zip", "country", "loan", "win", "bid", "icu", "buzz",
    "cam", "rest", "monster", "info", "live", "online", "site", "shop",
}

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "verification", "secure", "update",
    "account", "banking", "confirm", "password", "wallet", "suspend",
    "unlock", "invoice", "payment", "refund", "claim", "prize",
    "winner", "free", "bonus", "gift", "kyc", "otp", "recover",
]

# brand -> real domains
BRANDS = {
    "paypal": ["paypal.com"],
    "google": ["google.com", "gmail.com", "youtube.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "whatsapp": ["whatsapp.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "flipkart": ["flipkart.com"],
    "irctc": ["irctc.co.in"],
    "linkedin": ["linkedin.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "github": ["github.com"],
}


TRUSTED = {
    "google.com", "youtube.com", "gmail.com", "microsoft.com", "live.com",
    "outlook.com", "office.com", "apple.com", "icloud.com", "amazon.com",
    "amazon.in", "facebook.com", "instagram.com", "whatsapp.com",
    "linkedin.com", "github.com", "wikipedia.org", "netflix.com",
    "paypal.com", "flipkart.com", "paytm.com", "irctc.co.in",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "twitter.com",
    "x.com", "reddit.com", "stackoverflow.com", "anthropic.com",
}

LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def _edit_distance(a, b):
    if abs(len(a) - len(b)) > 2:
        return 99
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _entropy(text):
    import math
    if not text:
        return 0.0
    return -sum((text.count(c) / len(text)) * math.log2(text.count(c) / len(text)) for c in set(text))


def _registered_domain(host):
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "ac"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def analyze_url_rules(url):
    raw = url.strip()
    full = raw if raw.lower().startswith(("http://", "https://")) else "http://" + raw
    parsed = urlparse(full)
    host = (parsed.hostname or "").lower()
    path_query = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    reg = _registered_domain(host)
    tld = host.split(".")[-1] if "." in host else ""

    score = 0
    reasons = []

    def add(points, text):
        nonlocal score
        score += points
        reasons.append(text)

    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host) or re.fullmatch(r"0x[0-9a-f]+|\d{8,10}", host):
        add(45, "Uses an IP address instead of a domain name.")

    if host in SHORTENERS or reg in SHORTENERS:
        add(35, "Uses a URL shortener that hides the real destination.")

    if "@" in raw:
        add(35, "Contains an '@' symbol, which can hide the real destination.")

    if "xn--" in host:
        add(35, "Uses punycode (look-alike characters) in the domain.")

    if parsed.scheme == "http":
        add(15, "Does not use HTTPS.")

    if tld in SUSPICIOUS_TLDS:
        add(25, f"Uses a domain ending (.{tld}) that is common in phishing.")

    # brand impersonation
    for brand, real in BRANDS.items():
        if brand in host and reg not in real:
            add(45, f"Mentions '{brand}' but the real domain is not {real[0]}.")
            break

    hits = [w for w in SUSPICIOUS_WORDS if w in host or w in path_query.lower()]
    if hits:
        add(min(10 * len(hits), 30), "Contains risky words: " + ", ".join(hits[:4]) + ".")

    if host.count("-") >= 2:
        add(15, "Domain has many hyphens.")
    elif "-" in reg:
        add(8, "Domain contains a hyphen.")

    if len(host.split(".")) >= 4:
        add(20, "Has many sub-domains.")

    if len(raw) > 75:
        add(10, "Very long URL.")

    try:
        port = parsed.port
        bad_port = False
    except ValueError:
        port, bad_port = None, True
    if bad_port:
        add(20, "Has an invalid or unusual port in the URL.")
    elif raw.count("//") > 1 or port not in (None, 80, 443):
        add(10, "Unusual redirect or port in the URL.")

    if re.search(r"\.(exe|apk|scr|zip|msi|bat)(\?|$)", path_query.lower()):
        add(30, "Links directly to a downloadable file.")

    # --- Look-alike / typo-squatting (paypa1.com, amaz0n.com, gooogle.com) ---
    label = reg.split(".")[0]
    brand_names = list(BRANDS.keys())
    if reg not in TRUSTED and label:
        norm = label.translate(LEET)
        for b in brand_names:
            real = BRANDS[b]
            if reg in real:
                continue
            if (norm == b and label != b) or (len(label) >= 5 and 0 < _edit_distance(label, b) <= 1):
                add(50, f"Domain looks like a fake copy of '{b}'.")
                break

    # --- Random-looking domain (e.g. xk39sdf8.com) ---
    if len(label) >= 8 and _entropy(label) > 3.3 and sum(ch.isdigit() for ch in label) >= 2:
        add(35, "Domain name looks random-generated.")

    # --- Redirect hidden in the query (?url=http://...) ---
    if re.search(r"(?:url|redirect|next|goto|link|return)=https?", parsed.query.lower()):
        add(25, "Contains a hidden redirect to another site.")

    # --- Fake security words inside the domain ---
    if re.search(r"https?", host) or "www" in host.replace("www.", "", 1):
        add(15, "Domain contains fake 'https' or 'www' text.")

    # --- Many digits in the domain ---
    if sum(ch.isdigit() for ch in host) >= 5:
        add(15, "Domain has many digits.")

    # --- Trusted sites: avoid false alarms (never trusts IPs or '@' tricks) ---
    if reg in TRUSTED and parsed.scheme == "https" and "@" not in raw and len(host.split(".")) <= 3:
        return min(score, 10), []

    return min(score, 100), reasons

# ===== end of URL rule checks =====

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
DATA_DIR = Path("/tmp") if Path("/tmp").exists() else BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

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

    # Second opinion from rule checks (catches IPs, shorteners, fake brands...)
    rule_score, rule_reasons = analyze_url_rules(url)
    risk_percentage = max(risk_percentage, rule_score)

    if risk_percentage >= 60:
        result = "Phishing / Malicious URL"
    elif risk_percentage >= 35:
        result = "Suspicious URL"
    else:
        result = "Safe / Legitimate URL"

    feature_values["Rule_Findings"] = " ".join(rule_reasons) if rule_reasons else "None"

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
            risk += 25
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

    # ---- Extra checks (added) ----
    import re as _re

    # Account threats
    threat_words = [
        "suspended", "locked", "blocked", "deactivated", "disabled",
        "verify your account", "confirm your account", "unusual activity",
        "unauthorized", "kyc", "expire", "will be closed", "legal action",
        "arrest", "warrant"
    ]
    if any(w in message_lower for w in threat_words):
        risk += 20
        reasons.append("Threatens account problems or legal trouble.")

    # Call to action
    action_words = [
        "click here", "click the link", "click below", "tap here",
        "log in", "login", "sign in", "verify now", "update now",
        "confirm now", "claim now", "download", "install", "scan the qr"
    ]
    if any(w in message_lower for w in action_words):
        risk += 15
        reasons.append("Pushes you to click, log in or download something.")

    # Shortened or suspicious links
    link_hosts = _re.findall(r"(?:https?://|www\.)([^\s/]+)", message_lower)
    bad_tlds = (".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
                ".click", ".link", ".work", ".buzz", ".icu", ".zip")
    short = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly",
             "ow.ly", "is.gd", "rb.gy", "shorturl.at")
    if any(h.startswith(short) or h.endswith(bad_tlds) for h in link_hosts):
        risk += 20
        reasons.append("Contains a shortened or suspicious-looking link.")

    # Delivery / refund / tax lures
    lure_words = [
        "parcel", "package", "delivery failed", "refund", "tax refund",
        "customs fee", "pending delivery", "reschedule delivery",
        "unclaimed", "inheritance", "gift card", "crypto", "bitcoin"
    ]
    if any(w in message_lower for w in lure_words):
        risk += 15
        reasons.append("Uses a common delivery, refund or crypto lure.")

    # Asking for money / personal details
    ask_words = [
        "send money", "share your", "provide your", "enter your",
        "send us", "reply with", "processing fee", "claim fee",
        "pay a small fee", "pay the fee"
    ]
    if any(w in message_lower for w in ask_words):
        risk += 15
        reasons.append("Asks you to send money or personal details.")

    # Link combined with any other red flag is more serious
    has_link = bool(link_hosts)
    if has_link and len(reasons) >= 3:
        risk += 10

    # ---- More scam patterns (added) ----
    CLICK_MSG = "Pushes you to click, log in or download something."

    # "click on this link", "tap the link below", "open this link"
    if CLICK_MSG not in reasons and _re.search(
            r"\b(click|tap|open|visit|press)\b.{0,25}\b(link|here|below|url|website)\b", message_lower):
        risk += 20
        reasons.append(CLICK_MSG)

    # "you have won 10000 rupees", "congratulations", "lucky draw", "avail your prize"
    won_money = _re.search(r"\b(won|win|winner|selected|lucky)\b.{0,40}\b(rs\.?|rupees?|inr|usd|dollars?|lakh|crore|\d{3,})", message_lower)
    prize_bait = any(w in message_lower for w in [
        "congrat", "lucky draw", "avail your", "claim your", "you have won",
        "you won", "you are selected", "free recharge", "free iphone", "cash prize"
    ])
    if won_money or prize_bait:
        risk += 20
        reasons.append("Says you won money or a prize, a very common scam.")

    # Prize bait + a request to click is almost always a scam
    if (won_money or prize_bait or "prize" in message_lower) and CLICK_MSG in reasons:
        risk += 15

    # Limit risk to 100
    risk = min(risk, 100)

    # Final result
    if risk >= 50:
        result = "High Risk - Possible Scam"

    elif risk >= 25:
        result = "Suspicious Message"

    else:
        result = "Likely Safe"

    if not reasons:
        reasons.append("No major scam indicators were detected.")

    if risk >= 50:
        recommendation = (
            "Do not click links, share OTPs or provide personal information. "
            "Verify the sender through an official source."
        )

    elif risk >= 25:
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