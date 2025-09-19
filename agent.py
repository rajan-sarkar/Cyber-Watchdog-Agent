#!/usr/bin/env python3
"""
Cyber Watchdog Agent — API version
- Input: URL or path to a text/html file
- Output: Verdict + Reasons (English + Nepali)
- Uses: regex heuristics + HuggingFace zero-shot classification via Inference API
"""

import re
import os
import validators
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# --------- CONFIG ----------
HF_TOKEN = os.getenv("HF_API_TOKEN")  # set via env or hardcode
MODEL = "facebook/bart-large-mnli"   # zero-shot classification
CANDIDATE_LABELS = [
    "phishing",
    "malware",
    "credential harvesting",
    "spam",
    "benign",
    "suspicious"
]
API_URL = f"https://api-inference.huggingface.co/models/{MODEL}"
HEADERS = {"Authorization": f"Bearer {HF_TOKEN}"}
# ---------------------------

# Nepali translations
NEPALI_MAP = {
    "invalid_url": "अवैध URL",
    "redirects": "धेरै रिडाइरेक्टहरू (शंकास्पद)",
    "ip_in_domain": "डोमेनमा IP ठेगाना",
    "suspicious_tld": "सन्दिग्ध शीर्ष-स्तर डोमेन (TLD)",
    "phishing_words": "URL वा सामग्रीमा फिसिङ सम्बन्धी शब्दहरू",
    "many_hyphens": "डोमेनमा धेरै हाइफनहरू",
    "many_subdomains": "धेरै सब-डोमेनहरू",
    "obfuscated_js": "सन्केतित / अवहेलित JavaScript भेटियो",
    "credential_strings": "पासवर्ड/OTP/क्रेडेन्सियल खोजिएको",
    "data_uri": "डेटा URI / एम्बेडेड base64 फेला पर्‍यो",
    "embedded_scripts": "वेब पृष्ठमा स्क्रिप्ट/iframe फेला पर्‍यो",
    "classifier_phishing": "ML मोडलले फिसिङ प्रकारको संकेत दियो"
}

# -------------------------
# Functions for URL/text extraction & heuristics
# -------------------------

def extract_text_from_url(url, timeout=8):
    headers = {"User-Agent": "Mozilla/5.0 (compatible; CyberWatchdog/1.0)"}
    try:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
    except Exception as e:
        return None, f"fetch_error:{e}"

    final_url = r.url
    redirects = len(r.history)
    html = r.text
    soup = BeautifulSoup(html, "html.parser")
    for s in soup(["script", "style", "noscript"]):
        s.decompose()
    text = " ".join(soup.stripped_strings)
    title = soup.title.string.strip() if soup.title else ""
    return {
        "final_url": final_url,
        "redirects": redirects,
        "title": title,
        "text": text[:200000],
        "raw_html": html
    }, None

def heuristics_url(url):
    reasons = []
    parsed = urlparse(url)
    netloc = parsed.netloc.lower()
    if not validators.url(url):
        reasons.append(("invalid_url", "URL format invalid"))
        return reasons
    host = netloc.split(':')[0]
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        reasons.append(("ip_in_domain", "IP address in risky domain"))
    if re.search(r'\.(ru|cn|tk|ml|cf|gq)$', host, re.I):
        reasons.append(("suspicious_tld", "Suspicious TLD"))
    if re.search(r'(login|signin|secure|account|verify|update|confirm|bank|paypal|amazon|freegift)', url, re.I):
        reasons.append(("phishing_words", "Phishing-like keywords"))
    if host.count('-') > 2:
        reasons.append(("many_hyphens", "Many hyphens in domain"))
    if host.count('.') > 3:
        reasons.append(("many_subdomains", "Many subdomains"))
    return reasons

def heuristics_text(text, raw_html=""):
    reasons = []
    if re.search(r'(eval\s*\(|atob\s*\(|unescape\s*\(|new Function\s*\(|window\.location|document\.write|setTimeout\s*\()', raw_html, re.I):
        reasons.append(("obfuscated_js", "Obfuscated JS or redirector code"))
    if re.search(r'(password|passwd|pin|otp|one[-\s]*time|cvv|card number|credit card)', text, re.I):
        reasons.append(("credential_strings", "Credential harvesting indicators"))
    if re.search(r'data:text\/html;base64|src=["\']data:', raw_html, re.I):
        reasons.append(("data_uri", "Data URI or embedded base64"))
    if re.search(r'<iframe|<script', raw_html, re.I):
        reasons.append(("embedded_scripts", "Embedded script/iframe"))
    return reasons

# -------------------------
# Zero-shot classification with Hugging Face API
# -------------------------
def run_zero_shot(text, labels=CANDIDATE_LABELS):
    try:
        payload = {"inputs": text, "parameters": {"candidate_labels": labels}}
        response = requests.post(API_URL, headers=HEADERS, json=payload)
        if response.status_code != 200:
            return {"error": response.text}
        return response.json()
    except Exception as e:
        return {"error": str(e)}

# -------------------------
# -------------------------
# Aggregate & verdict function
# -------------------------
# -------------------------
# Aggregate & verdict function
# -------------------------
def aggregate_and_explain(url=None, file_text=None):
    reasons = []
    source_text = ""
    meta = {}

    # ---------------- Input extraction ----------------
    if url:
        if not validators.url(url):
            return {
                "verdict": "invalid",
                "english": "Invalid URL format.",
                "nepali": NEPALI_MAP["invalid_url"],
                "details": [],
                "meta": {}
            }
        extracted, err = extract_text_from_url(url)
        if err:
            return {
                "verdict": "error",
                "english": f"Could not fetch URL: {err}",
                "nepali": "URL पहुँच गर्न सकिएन",
                "details": [],
                "meta": {}
            }
        meta = extracted
        source_text = extracted.get("text", "")
        reasons += heuristics_url(extracted.get("final_url", url))
        reasons += heuristics_text(source_text, extracted.get("raw_html", ""))
        if extracted.get("redirects", 0) > 3:
            reasons.append(("redirects", "Multiple redirects"))
    elif file_text:
        source_text = file_text
        reasons += heuristics_text(source_text, source_text)
    else:
        return {
            "verdict": "error",
            "english": "No input provided.",
            "nepali": "कुनै इनपुट छैन",
            "details": [],
            "meta": {}
        }

    # ---------------- Zero-shot classification ----------------
    excerpt = source_text[:4000] if len(source_text) > 4000 else source_text
    cls = run_zero_shot(excerpt)

    classifier_reason = None
    if "error" in cls:
        classifier_reason = ("classifier_error", cls["error"])
    else:
        top_label = cls["labels"][0]
        top_score = cls["scores"][0]
        classifier_reason = (top_label, top_score)
        if top_label.lower() in ("phishing", "malware", "credential harvesting", "suspicious") and top_score > 0.5:
            reasons.append(("classifier_phishing", f"{top_label} ({top_score:.2f})"))

    # ---------------- Scoring & Verdict ----------------
    score = 0.18 * len(reasons)
    if isinstance(classifier_reason, tuple) and isinstance(classifier_reason[1], float):
        score += classifier_reason[1] * 0.4

    verdict = "safe" if score < 0.5 else "unsafe"

    # ---------------- Build summaries ----------------
    eng_lines, nep_lines, detail_list = [], [], []

    if verdict == "safe":
        eng_lines.append("Looks mostly safe based on current heuristics and ML check.")
        nep_lines.append("हालको जाँच अनुसार सुरक्षित देखिन्छ।")
    else:
        eng_lines.append("Potentially unsafe.")
        nep_lines.append("संभावित रुपमा असुरक्षित।")

    # Always add heuristic reasons to details (for tabs)
    for r in reasons:
        code, extra = r[0], r[1] if len(r) > 1 else ""
        detail_list.append({
            "code": code,
            "english": f"{code}: {extra}",
            "nepali": f"{NEPALI_MAP.get(code, code)} — {extra}"
        })

    # Add classifier info to details
    if classifier_reason:
        ml_code, ml_extra = classifier_reason
        if isinstance(ml_extra, float):
            ml_extra_str = f"{ml_extra:.2f}"
        else:
            ml_extra_str = str(ml_extra)
        detail_list.append({
            "code": "ml_label",
            "english": f"ML label: {ml_extra_str}",
            "nepali": f"ML लेबल: {ml_extra_str}"
        })

    return {
        "verdict": verdict,
        "english": "\n".join(eng_lines),
        "nepali": "\n".join(nep_lines),
        "details": detail_list,
        "meta": {
            "final_url": meta.get("final_url", url),
            "title": meta.get("title", ""),
            "redirects": meta.get("redirects", 0),
            "text_snippet": source_text[:500],
            "raw_html_snippet": meta.get("raw_html", "")[:500]
        }
    }




# -------------------------
# Flask expects classify_text
# -------------------------
def classify_text(text, candidate_labels=None):
    """
    Wrapper so app.py can import classify_text().
    Uses aggregate_and_explain under the hood.
    """
    if text.startswith("http"):
        return aggregate_and_explain(url=text)
    else:
        return aggregate_and_explain(file_text=text)

# -------------------------
# CLI
# -------------------------
if __name__ == "__main__":
    print("Cyber Watchdog — enter a URL or type 'file:<path>' to scan a local file. Type 'exit' to quit.")
    while True:
        s = input("\nInput> ").strip()
        if not s or s.lower() == "exit":
            print("Good luck. Stay secure.")
            break
        if s.lower().startswith("file:"):
            path = s[5:].strip()
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    data = fh.read()
            except Exception as e:
                print("Could not open file:", e)
                continue
            result = aggregate_and_explain(file_text=data)
        else:
            if not s.startswith("http"):
                s = "http://" + s
            result = aggregate_and_explain(url=s)

        print("\n===== VERDICT =====")
        print("[English]\n", result["english"])
        print("\n[Nepali]\n", result["nepali"])
        print("\n[Details JSON snippet]\n", result["details"])
        if "meta" in result and result["meta"]:
            print("\n[Meta]\n", {k: result["meta"].get(k) for k in ("final_url","redirects","title")})
