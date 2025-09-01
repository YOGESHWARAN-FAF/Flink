import requests
import whois
import socket
import datetime
import tldextract
import urllib.parse
import google.generativeai as genai

# =============== CONFIGURATION ===============
GEMINI_API_KEY = "Replace with your Gemini API Key"   #<-- Replace with your Gemini API Key
VT_API_KEY = " Replace with your VirusTotal Key (optional)"   # <-- Replace with your VirusTotal Key (optional)

# Configure Gemini
genai.configure(api_key=GEMINI_API_KEY)


class LinkAnalyzer:
    def __init__(self, url):
        # Clean and parse the URL
        self.url = url.strip()
        if not self.url.startswith(("http://", "https://")):
            self.url = "http://" + self.url
        self.parsed_url = urllib.parse.urlparse(self.url)

        # Extract clean domain (e.g., google.com)
        ext = tldextract.extract(self.url)
        self.domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

    # ---------------- CHECK HTTPS ----------------
    def check_https(self):
        return self.parsed_url.scheme == "https"

    # ---------------- DOMAIN AGE ----------------
    def get_domain_age(self):
        try:
            w = whois.whois(self.domain)
            creation_date = None
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date
            if creation_date:
                age_days = (datetime.datetime.now() - creation_date).days
                return f"{age_days} days old"
            else:
                return "Unknown"
        except Exception:
            return "WHOIS info not available"

    # ---------------- WHOIS INFO ----------------
    def get_whois_info(self):
        try:
            w = whois.whois(self.domain)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": list(w.name_servers) if w.name_servers else [],
            }
        except Exception:
            return "WHOIS lookup failed"

    # ---------------- IP ADDRESS ----------------
    def get_ip(self):
        try:
            return socket.gethostbyname(self.domain)
        except Exception:
            return "IP not found"

    # ---------------- BLACKLIST CHECK ----------------
    def check_blacklist(self):
        try:
            resp = requests.post(
                "https://urlhaus-api.abuse.ch/v1/url/", data={"url": self.url}, timeout=10
            )
            if resp.status_code == 200 and "blacklist" in resp.text.lower():
                return "⚠️ Blacklisted"
            return "Not in blacklist"
        except Exception:
            return "Blacklist check failed"

    # ---------------- VIRUS SCAN (VirusTotal API) ----------------
    def check_virustotal(self):
        if not VT_API_KEY or VT_API_KEY == "YOUR_VIRUSTOTAL_KEY_HERE":
            return "Skipped (no API key)"
        try:
            headers = {"x-apikey": VT_API_KEY}
            # First, submit the URL for scanning
            scan_resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": self.url},
                timeout=15,
            )
            if scan_resp.status_code == 200:
                scan_id = scan_resp.json()["data"]["id"]

                # Then fetch the results
                result_resp = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
                    headers=headers,
                    timeout=15,
                )
                if result_resp.status_code == 200:
                    stats = result_resp.json()["data"]["attributes"]["stats"]
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)

                    if malicious > 0 or suspicious > 0:
                        return f"⚠️ Malicious ({malicious} malicious, {suspicious} suspicious, {harmless} harmless)"
                    return f"✅ Clean ({harmless} engines marked harmless)"
            return "❌ VirusTotal scan failed"
        except Exception:
            return "VirusTotal check failed"

    # ---------------- AI ANALYSIS ----------------
    def ai_analysis(self, details):
        try:
            prompt = f"""
            Analyze the following URL security report and provide:
            - Is this URL safe or a scam?
            - Explanation based on: domain age, HTTPS, WHOIS, blacklist, VirusTotal, IP.
            - Risk Score (0 = very safe, 100 = highly risky).
            - A short conclusion for the user.
            -give the content like user friendly should not ** any star symbols be in the content  and give the each point with a related emoji

            URL Report:
            {details}
            """

            model = genai.GenerativeModel("gemini-2.0-flash")
            response = model.generate_content(prompt)
            return response.text.strip()
        except Exception as e:
            return f"AI analysis failed: {e}"

    # ---------------- FULL ANALYSIS ----------------
    def analyze(self):
        result = {
            "url": self.url,
            "domain": self.domain,
            "https": self.check_https(),
            "domain_age": self.get_domain_age(),
            "ip_address": self.get_ip(),
            "whois": self.get_whois_info(),
            "blacklist": self.check_blacklist(),
            "virustotal": self.check_virustotal(),
        }

        # AI Final Analysis
        ai_result = self.ai_analysis(result)
        result["ai_result"] = ai_result

        return result
