<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>AI-Based Phishing Detection & Cyber Safety Analyzer</title>

    <script src="https://unpkg.com/lucide@latest"></script>

    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: Arial, Helvetica, sans-serif;
            background: #f5f8fc;
            color: #172033;
            line-height: 1.6;
        }

        a {
            text-decoration: none;
            color: inherit;
        }

        .wrap {
            width: min(1180px, 92%);
            margin: auto;
        }

        /* ================= HEADER ================= */

        header {
            background: #0b1f3a;
            color: white;
            padding: 30px 0 22px;
        }

        .brand-area {
            text-align: center;
        }

        .brand-icon {
            width: 64px;
            height: 64px;
            margin: 0 auto 15px;
            border-radius: 16px;
            background: rgba(37, 99, 235, 0.18);
            border: 1px solid rgba(96, 165, 250, 0.35);
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .brand-icon svg {
            width: 34px;
            height: 34px;
            color: #60a5fa;
        }

        .brand-area h1 {
            font-size: 28px;
            font-weight: 700;
            letter-spacing: -0.4px;
        }

        .brand-area p {
            margin-top: 6px;
            color: #b8c7dc;
            font-size: 15px;
        }

        /* ================= NAVIGATION ================= */

        .links {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
            margin-top: 25px;
        }

        .links a {
            display: inline-flex;
            align-items: center;
            gap: 7px;
            padding: 9px 13px;
            border-radius: 8px;
            color: #d9e4f3;
            font-size: 13px;
            font-weight: 600;
            transition: 0.2s ease;
        }

        .links a:hover {
            background: rgba(255, 255, 255, 0.08);
            color: white;
        }

        .links svg {
            width: 16px;
            height: 16px;
        }

        /* ================= HERO ================= */

        .hero {
            padding: 70px 0 45px;
            text-align: center;
        }

        .hero-icon {
            width: 62px;
            height: 62px;
            margin: 0 auto 18px;
            border-radius: 16px;
            background: #eaf2ff;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .hero-icon svg {
            width: 31px;
            height: 31px;
            color: #2563eb;
        }

        .hero-label {
            display: inline-flex;
            align-items: center;
            gap: 7px;
            color: #2563eb;
            font-size: 12px;
            font-weight: 800;
            letter-spacing: 1.5px;
            margin-bottom: 10px;
        }

        .hero-label svg {
            width: 15px;
            height: 15px;
        }

        .hero h2 {
            font-size: clamp(34px, 5vw, 54px);
            line-height: 1.1;
            color: #0b1f3a;
            letter-spacing: -1.5px;
        }

        .hero p {
            max-width: 690px;
            margin: 18px auto 0;
            color: #66758a;
            font-size: 17px;
        }

        /* ================= ANALYZER ================= */

        .analyzer {
            background: white;
            border: 1px solid #e2e9f2;
            border-radius: 18px;
            padding: 30px;
            box-shadow: 0 12px 35px rgba(11, 31, 58, 0.06);
        }

        .input-label {
            display: flex;
            align-items: center;
            gap: 8px;
            color: #0b1f3a;
            font-weight: 700;
            margin-bottom: 12px;
        }

        .input-label svg {
            width: 18px;
            color: #2563eb;
        }

        .url-form {
            display: flex;
            gap: 12px;
        }

        .url-input {
            flex: 1;
            min-width: 0;
            height: 58px;
            border: 1px solid #cfd9e6;
            border-radius: 10px;
            padding: 0 18px;
            font-size: 16px;
            outline: none;
            background: #fbfdff;
            color: #172033;
            transition: 0.2s ease;
        }

        .url-input:focus {
            border-color: #2563eb;
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }

        .analyze-btn {
            height: 58px;
            padding: 0 26px;
            border: none;
            border-radius: 10px;
            background: #2563eb;
            color: white;
            font-size: 15px;
            font-weight: 700;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 9px;
            transition: 0.2s ease;
            white-space: nowrap;
        }

        .analyze-btn:hover {
            background: #1d4ed8;
            transform: translateY(-1px);
        }

        .analyze-btn svg {
            width: 18px;
        }

        .analyzer-note {
            display: flex;
            align-items: center;
            gap: 7px;
            margin-top: 13px;
            color: #718096;
            font-size: 12px;
        }

        .analyzer-note svg {
            width: 15px;
        }

        /* ================= WIDGETS ================= */

        .widgets {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 18px;
            margin: 25px 0 70px;
        }

        .widget {
            background: white;
            border: 1px solid #e2e9f2;
            border-radius: 14px;
            padding: 23px;
            min-height: 155px;
            transition: 0.2s ease;
        }

        .widget:hover {
            transform: translateY(-3px);
            box-shadow: 0 12px 25px rgba(11, 31, 58, 0.06);
        }

        .widget-icon {
            width: 43px;
            height: 43px;
            border-radius: 10px;
            background: #eaf2ff;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 16px;
        }

        .widget-icon svg {
            width: 21px;
            color: #2563eb;
        }

        .widget h3 {
            color: #0b1f3a;
            font-size: 16px;
            margin-bottom: 6px;
        }

        .widget p {
            color: #718096;
            font-size: 13px;
            line-height: 1.5;
        }

        /* ================= RESULT ================= */

        .result-card {
            margin-top: 25px;
            border: 1px solid #dce5ef;
            border-radius: 14px;
            padding: 25px;
            background: #f9fbfe;
        }

        .result-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 15px;
            margin-bottom: 18px;
        }

        .result-title {
            display: flex;
            align-items: center;
            gap: 9px;
            color: #0b1f3a;
            font-size: 18px;
            font-weight: 700;
        }

        .result-title svg {
            color: #2563eb;
        }

        .risk-badge {
            padding: 7px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 700;
            background: #eaf2ff;
            color: #1d4ed8;
        }

        .result-url {
            padding: 13px 15px;
            background: white;
            border: 1px solid #e2e9f2;
            border-radius: 8px;
            word-break: break-all;
            color: #536174;
            font-size: 13px;
        }

        .risk-score {
            margin-top: 20px;
        }

        .risk-score-top {
            display: flex;
            justify-content: space-between;
            font-size: 13px;
            font-weight: 700;
            color: #344054;
            margin-bottom: 8px;
        }

        .risk-bar {
            height: 9px;
            background: #e5eaf1;
            border-radius: 10px;
            overflow: hidden;
        }

        .risk-fill {
            height: 100%;
            width: {{ risk_percentage|default(0) }}%;
            background: #2563eb;
            border-radius: 10px;
        }

        .reasons {
            margin-top: 22px;
        }

        .reasons h4 {
            color: #0b1f3a;
            margin-bottom: 10px;
        }

        .reasons ul {
            padding-left: 20px;
            color: #59687b;
            font-size: 14px;
        }

        /* ================= ABOUT ================= */

        .about {
            background: #0b1f3a;
            color: white;
            padding: 70px 0;
        }

        .about-inner {
            max-width: 850px;
        }

        .about-label {
            color: #60a5fa;
            font-size: 12px;
            font-weight: 800;
            letter-spacing: 1.5px;
            margin-bottom: 10px;
        }

        .about h2 {
            font-size: 34px;
            margin-bottom: 15px;
        }

        .about > .wrap > .about-inner > p {
            color: #bdc9d9;
            font-size: 16px;
            line-height: 1.8;
        }

        .about-features {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 18px;
            margin-top: 32px;
        }

        .about-feature {
            padding: 20px;
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            background: rgba(255,255,255,0.04);
        }

        .about-feature svg {
            width: 22px;
            color: #60a5fa;
            margin-bottom: 12px;
        }

        .about-feature h3 {
            font-size: 15px;
            margin-bottom: 5px;
        }

        .about-feature p {
            color: #aebcd0;
            font-size: 13px;
        }

        /* ================= DISCLAIMER ================= */

        .disclaimer {
            padding: 25px 0;
            background: #eef3f8;
        }

        .disclaimer-inner {
            display: flex;
            align-items: center;
            gap: 10px;
            color: #637186;
            font-size: 12px;
        }

        .disclaimer svg {
            width: 17px;
            flex-shrink: 0;
        }

        /* ================= FOOTER ================= */

        footer {
            background: #07172b;
            color: #94a5bc;
            padding: 25px 0;
            text-align: center;
            font-size: 12px;
        }

        /* ================= RESPONSIVE ================= */

        @media (max-width: 900px) {

            .widgets {
                grid-template-columns: repeat(2, 1fr);
            }

            .about-features {
                grid-template-columns: 1fr;
            }

            .links {
                gap: 4px;
            }
        }

        @media (max-width: 650px) {

            header {
                padding: 24px 0 18px;
            }

            .brand-area h1 {
                font-size: 21px;
                line-height: 1.3;
            }

            .brand-area p {
                font-size: 13px;
            }

            .links {
                justify-content: flex-start;
                overflow-x: auto;
                flex-wrap: nowrap;
                padding-bottom: 5px;
            }

            .links a {
                flex-shrink: 0;
                font-size: 12px;
            }

            .hero {
                padding: 48px 0 30px;
            }

            .hero h2 {
                font-size: 35px;
            }

            .hero p {
                font-size: 15px;
            }

            .analyzer {
                padding: 20px;
            }

            .url-form {
                flex-direction: column;
            }

            .analyze-btn {
                width: 100%;
            }

            .widgets {
                grid-template-columns: 1fr;
                margin-bottom: 50px;
            }

            .result-header {
                align-items: flex-start;
                flex-direction: column;
            }

            .about {
                padding: 50px 0;
            }

            .about h2 {
                font-size: 28px;
            }

            .disclaimer-inner {
                align-items: flex-start;
            }
        }
    </style>
</head>

<body>

    <!-- ================= HEADER ================= -->

    <header>
        <div class="wrap">

            <div class="brand-area">

                <div class="brand-icon">
                    <i data-lucide="shield-check"></i>
                </div>

                <h1>
                    AI-Based Phishing Detection & Cyber Safety Analyzer
                </h1>

                <p>
                    Smart protection against phishing, scams and suspicious links
                </p>

            </div>

            <nav class="links">

                <a href="/">
                    <i data-lucide="link"></i>
                    URL Analyzer
                </a>

                <a href="/qr-scanner">
                    <i data-lucide="qr-code"></i>
                    QR Scanner
                </a>

                <a href="/message-detector">
                    <i data-lucide="message-square"></i>
                    Message Detector
                </a>

                <a href="/safety-tips">
                    <i data-lucide="shield"></i>
                    Safety Tips
                </a>

                <a href="/quiz">
                    <i data-lucide="clipboard-check"></i>
                    Quiz
                </a>

                <a href="/features">
                    <i data-lucide="layout-grid"></i>
                    Features
                </a>

                <a href="/history">
                    <i data-lucide="history"></i>
                    History
                </a>

            </nav>

        </div>
    </header>


    <!-- ================= HERO ================= -->

    <main>

        <section class="hero">

            <div class="wrap">

                <div class="hero-icon">
                    <i data-lucide="shield-check"></i>
                </div>

                <div class="hero-label">
                    <i data-lucide="scan-search"></i>
                    INTELLIGENT URL ANALYSIS
                </div>

                <h2>
                    Analyze Before You Trust.
                </h2>

                <p>
                    Analyze suspicious website URLs using machine-learning
                    based security signals before you click or share sensitive information.
                </p>

            </div>

        </section>


        <!-- ================= ANALYZER ================= -->

        <section>
            <div class="wrap">

                <div class="analyzer">

                    <div class="input-label">
                        <i data-lucide="globe-2"></i>
                        Enter a website URL
                    </div>

                    <!-- IMPORTANT: matches Flask route -->
                    <form
                        action="/analyze-url"
                        method="POST"
                        class="url-form"
                    >

                        <input
                            class="url-input"
                            type="text"
                            name="url"
                            placeholder="https://example.com"
                            autocomplete="off"
                            required
                        >

                        <button
                            type="submit"
                            class="analyze-btn"
                        >
                            <i data-lucide="search-check"></i>
                            Analyze URL
                        </button>

                    </form>

                    <div class="analyzer-note">
                        <i data-lucide="info"></i>
                        URL analysis uses website address characteristics — no browsing required.
                    </div>


                    <!-- ================= RESULT ================= -->

                    {% if result %}

                    <div class="result-card">

                        <div class="result-header">

                            <div class="result-title">
                                <i data-lucide="shield-alert"></i>
                                Analysis Result
                            </div>

                            <div class="risk-badge">
                                {{ result }}
                            </div>

                        </div>

                        <div class="result-url">
                            {{ analyzed_url }}
                        </div>

                        <div class="risk-score">

                            <div class="risk-score-top">
                                <span>Risk Score</span>
                                <span>{{ risk_percentage }}%</span>
                            </div>

                            <div class="risk-bar">
                                <div class="risk-fill"></div>
                            </div>

                        </div>


                        {% if features %}

                        <div class="reasons">

                            <h4>Detected URL Features</h4>

                            <ul>
                                {% for key, value in features.items() %}
                                <li>
                                    <strong>{{ key }}:</strong> {{ value }}
                                </li>
                                {% endfor %}
                            </ul>

                        </div>

                        {% endif %}

                    </div>

                    {% endif %}


                    <!-- ================= ERROR ================= -->

                    {% if error %}

                    <div class="result-card">

                        <div class="result-title">
                            <i data-lucide="circle-alert"></i>
                            Analysis Error
                        </div>

                        <p style="margin-top: 10px; color: #66758a;">
                            {{ error }}
                        </p>

                    </div>

                    {% endif %}

                </div>


                <!-- ================= WIDGETS ================= -->

                <div class="widgets">

                    <div class="widget">

                        <div class="widget-icon">
                            <i data-lucide="scan-search"></i>
                        </div>

                        <h3>
                            Intelligent Analysis
                        </h3>

                        <p>
                            Examines multiple URL characteristics to identify suspicious patterns.
                        </p>

                    </div>


                    <div class="widget">

                        <div class="widget-icon">
                            <i data-lucide="shield-alert"></i>
                        </div>

                        <h3>
                            Threat Detection
                        </h3>

                        <p>
                            Helps identify patterns commonly associated with phishing websites.
                        </p>

                    </div>


                    <div class="widget">

                        <div class="widget-icon">
                            <i data-lucide="gauge"></i>
                        </div>

                        <h3>
                            Risk Scoring
                        </h3>

                        <p>
                            Provides an easy-to-understand percentage-based risk score.
                        </p>

                    </div>


                    <div class="widget">

                        <div class="widget-icon">
                            <i data-lucide="zap"></i>
                        </div>

                        <h3>
                            Fast Analysis
                        </h3>

                        <p>
                            Analyze a URL quickly without directly browsing the website.
                        </p>

                    </div>

                </div>

            </div>
        </section>


        <!-- ================= ABOUT ================= -->

        <section class="about">

            <div class="wrap">

                <div class="about-inner">

                    <div class="about-label">
                        ABOUT CYBERSHIELD
                    </div>

                    <h2>
                        A smarter way to pause before you click.
                    </h2>

                    <p>
                        CyberShield Analyzer is designed to help users identify
                        potentially dangerous URLs, suspicious messages and other
                        common online threats. The project combines machine-learning
                        analysis with practical cyber-safety awareness features.
                    </p>


                    <div class="about-features">

                        <div class="about-feature">

                            <i data-lucide="brain"></i>

                            <h3>
                                Machine Learning
                            </h3>

                            <p>
                                Uses a trained model to estimate phishing risk from URL characteristics.
                            </p>

                        </div>


                        <div class="about-feature">

                            <i data-lucide="layers-3"></i>

                            <h3>
                                Multi-Signal Analysis
                            </h3>

                            <p>
                                Considers multiple URL signals instead of relying on a single indicator.
                            </p>

                        </div>


                        <div class="about-feature">

                            <i data-lucide="graduation-cap"></i>

                            <h3>
                                Security Awareness
                            </h3>

                            <p>
                                Includes safety tips and an awareness quiz to encourage safer online habits.
                            </p>

                        </div>

                    </div>

                </div>

            </div>

        </section>


        <!-- ================= DISCLAIMER ================= -->

        <section class="disclaimer">

            <div class="wrap">

                <div class="disclaimer-inner">

                    <i data-lucide="triangle-alert"></i>

                    <span>
                        This tool provides an automated security assessment and should not be treated as a guarantee that a website is safe or malicious. Always verify suspicious links independently.
                    </span>

                </div>

            </div>

        </section>

    </main>


    <!-- ================= FOOTER ================= -->

    <footer>

        <div class="wrap">
            AI-Based Phishing Detection & Cyber Safety Analyzer
        </div>

    </footer>


    <script>
        lucide.createIcons();
    </script>

</body>
</html>