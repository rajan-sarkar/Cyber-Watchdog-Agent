# 🐺 Cyber Watchdog Agent  

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.3-green?logo=flask&logoColor=white)
![HuggingFace](https://img.shields.io/badge/HuggingFace-API-orange?logo=huggingface&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

### 🐺Cyber Watchdog Agent is a **web-based cyber threat classifier** that helps detect and explain potentially harmful content such as **phishing, malware, spam, and credential harvesting attempts**.  
It leverages **Hugging Face Transformers** with the **facebook/bart-large-mnli** model for **zero-shot text classification**.  

The project provides a sleek UI with **dark/light mode toggle**, a user friendly UI, and expandable technical details for advanced users.  

---

## 🚀 Features  
- ✅ Detects and classifies text into categories:  
  - Phishing  
  - Malware  
  - Credential Harvesting  
  - Spam  
  - Benign (Safe)  
  - Suspicious  

- ✅ Multi-language summary (English + Nepali)  
- ✅ Verdict display (SAFE / SUSPICIOUS / MALICIOUS)  
- ✅ Expandable **Technical & Meta Details** section  
- ✅ Dark/Light mode toggle  

---

## 🛠️ Tech Stack  
- **Backend:** Flask (Python)  
- **Frontend:** HTML + Tailwind CSS + JavaScript  
- **Model:** [facebook/bart-large-mnli](https://huggingface.co/facebook/bart-large-mnli) (Zero-shot Classification)  
- **API:** Hugging Face Inference API  
- **Environment Management:** `.env` file with `python-dotenv`  

---

## 📦 Installation & Setup  

### 1. Clone the repo

git clone https://github.com/rajan-sarkar/Cyber-Watchdog-Agent.git
cd Cyber-Watchdog-Agent


## 📸 Screenshot

(Demo screenshot will be  available later)

---



# The project provides:

🛡️ Real-time classification of text/URLs

🌐 Summaries in both English and Nepali for accessibility

⚙️ Expandable technical details for developers, researchers, and security learners

# This makes it useful for:

Students & researchers learning about phishing and safe-browsing systems

Cybersecurity hobbyists who want to analyze suspicious links

⚠️ Security Notice

Do NOT commit your Hugging Face API token to GitHub.

Add .env to .gitignore to avoid leaking secrets.

GitHub Push Protection will block you if you accidentally commit secrets.

📜 License

This project is licensed under the MIT License. You are free to use, modify, and distribute it.

🌟 Acknowledgments

Hugging Face
 for providing amazing NLP models.

Inspiration from real-world cybersecurity monitoring agents.

 

