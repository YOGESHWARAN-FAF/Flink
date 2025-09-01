🔗 AI Fake Link Detector

This project is a simple web app that helps you check if a link is safe or suspicious using:

✅ Google Gemini AI (for content analysis)

🛡️ VirusTotal API (for virus/malware detection)

🌍 WHOIS lookup (to check domain details)

Perfect for spotting phishing links, fake websites, or malicious URLs.

🚀 Features

🔍 Checks if a URL looks phishy or safe with AI

🛡️ Scans link against VirusTotal antivirus engines

🌐 Shows WHOIS domain info (age, registrar, expiry date)

📊 Returns a final verdict (Safe ✅ or Suspicious ⚠️)

🎨 Clean Bootstrap UI for easy use

⚙️ Setup

Clone this repo

git clone https://github.com/your-username/ai-fake-link-detector.git
cd ai-fake-link-detector


Install dependencies

pip install -r requirements.txt


Add your API keys in app.py

VT_API_KEY = "your_virustotal_api_key"
GEMINI_API_KEY = "your_gemini_api_key"


Run the Flask app

python app.py


Open in your browser:

http://127.0.0.1:5000

🧪 Example Results

Safe Link:

✅ Clean (68 engines marked harmless)
WHOIS: Google LLC, created 1997, expires 2028
Gemini Verdict: Safe website, widely trusted


Suspicious Link:

⚠️ Malicious (5 malicious, 2 suspicious, 61 harmless)
WHOIS: Random Registrar, created 3 days ago
Gemini Verdict: Looks like a phishing page

📌 Notes

Free VirusTotal API key allows 4 requests per minute.

WHOIS info may be hidden for some domains.

This is a helper tool, always double-check before clicking strange links.

🛠️ Tech Stack

Flask (Python backend)

Bootstrap (UI)

Google Gemini API (AI analysis)

VirusTotal API (malware scan)

WHOIS library (domain lookup)

👨‍💻 Author

Built with ❤️ by YOGESHWARAN
