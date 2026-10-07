Copy these five HTML files into your project's templates/ folder:
qr_scanner.html, message_detector.html, safety_tips.html, quiz.html, features.html.
Keep your existing index.html and history.html.

Your app.py needs GET routes:
  /qr-scanner -> qr_scanner.html
  /message-detector -> message_detector.html
  /safety-tips -> safety_tips.html
  /quiz -> quiz.html
  /features -> features.html

Your existing POST routes should handle /scan-qr and /analyze-message.
Note: the QR route analyzes decoded content as a URL; QR codes containing plain text may not be handled correctly by the URL feature extractor.
