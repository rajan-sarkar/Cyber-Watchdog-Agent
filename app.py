from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
from agent import classify_text
from flask_session import Session

app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cyber Watchdog</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #121212;
            color: #f0f0f0;
            transition: background 0.3s, color 0.3s;
        }
        body.light {
            background-color: #ffffff;
            color: #000000;
        }
        .container {
            max-width: 900px;
            margin: auto;
            padding: 20px;
        }
        h1 {
            text-align: center;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }
        .logo img {
            height: 50px;
        }
        textarea {
            width: 100%;
            padding: 10px;
            font-size: 16px;
        }
        button {
            background: #00ff88;
            border: none;
            padding: 10px 20px;
            font-size: 16px;
            margin-top: 10px;
            cursor: pointer;
            border-radius: 5px;
        }
        button:hover {
            background: #00cc66;
        }
        .toggle {
            position: absolute;
            top: 20px;
            right: 20px;
        }
        .details {
            margin-top: 20px;
        }
        details {
            background: #1e1e1e;
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
        }
        body.light details {
            background: #f4f4f4;
        }
    </style>
</head>
<body class="{{ 'light' if mode == 'light' else 'dark' }}">
    <div class="toggle">
        <form method="POST" action="{{ url_for('toggle_mode') }}" id="modeForm">
            <label>
                <input type="checkbox" id="modeToggle" name="mode" value="light" {% if mode == 'light' %}checked{% endif %}>
                🌙/☀️
            </label>
        </form>
    </div>
    <div class="container">
        <h1 class="logo">
            <img id="watchdogLogo" src="{{ url_for('static', filename='logo-dark.png') }}" alt="Cyber Watchdog Logo">
            🐾 Cyber Watchdog
        </h1>
        <form method="POST" action="/classify">
            <label for="text">Enter text/URL:</label><br><br>
            <textarea name="text" rows="4" required></textarea><br>
            <button type="submit">Classify</button>
        </form>
        {% if result %}
        <div class="result">
            <h2>Verdict: {{ result['verdict'] | upper }}</h2>
            <p><strong>English Summary:</strong> {{ result['english'] }}</p>
            <p><strong>Nepali Summary:</strong> {{ result['nepali'] }}</p>

            <details>
                <summary><strong>Show Technical & Meta Details</strong></summary>
                <h3>Technical Details:</h3>
                <ul>
                {% for item in result['details'] %}
                    <li>{{ item['english'] }}</li>
                {% endfor %}
                </ul>
                <h3>Meta Info:</h3>
                <pre>{{ result['meta'] | tojson(indent=2) }}</pre>
            </details>
        </div>
        {% endif %}
    </div>
    <script>
        const modeToggle = document.getElementById('modeToggle');
        const logo = document.getElementById('watchdogLogo');

        function updateLogo() {
            if (document.body.classList.contains("light")) {
                logo.src = "{{ url_for('static', filename='logo-light.png') }}";
            } else {
                logo.src = "{{ url_for('static', filename='logo-dark.png') }}";
            }
        }

        modeToggle.addEventListener('change', () => {
            document.getElementById('modeForm').submit();
        });

        window.addEventListener("load", updateLogo);
    </script>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def home():
    mode = session.get("mode", "dark")
    return render_template_string(HTML_PAGE, mode=mode, result=None)

@app.route("/classify", methods=["POST"])
def classify():
    mode = session.get("mode", "dark")
    text = request.form.get("text")
    candidate_labels = ["phishing", "malware", "benign"]

    if not text:
        return render_template_string(
            HTML_PAGE,
            mode=mode,
            result={
                "verdict": "invalid",
                "english": "No text provided",
                "nepali": "कुनै पाठ उपलब्ध छैन",
                "details": [],
                "meta": {},
            },
        )

    result = classify_text(text, candidate_labels)
    return render_template_string(HTML_PAGE, mode=mode, result=result)

@app.route("/toggle_mode", methods=["POST"])
def toggle_mode():
    session["mode"] = "light" if request.form.get("mode") == "light" else "dark"
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)
