from flask import Flask, render_template, request
import re
import math
import hashlib
import requests
import random
import string


app = Flask(__name__)

def generate_strong_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

@app.route('/', methods=['GET', 'POST'])
def home():
    strength = ""
    entropy = 0
    crack_time = ""
    breach_status = ""
    strength_percent = 0
    suggested_password = ""


    if request.method == 'POST':
        password = request.form['password']
        charset = 0
        length = len(password)

        # Character checks
        if re.search(r"[A-Z]", password):
            charset += 26
        if re.search(r"[a-z]", password):
            charset += 26
        if re.search(r"[0-9]", password):
            charset += 10
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            charset += 32

        # Entropy calculation
        if charset > 0:
            entropy = round(length * math.log2(charset), 2)

        # Strength classification
        if entropy < 28:
            strength = "Very Weak"
        elif entropy < 36:
            strength = "Weak"
        elif entropy < 60:
            strength = "Medium"
        elif entropy < 128:
            strength = "Strong"
        else:
            strength = "Very Strong"

        suggested_password = ""

        if strength in ["Very Weak", "Weak", "Medium"]:
            suggested_password = generate_strong_password()


        # Convert entropy to percentage (max 128 bits)
        strength_percent = min(int((entropy / 128) * 100), 100)

        # Crack time estimation
        if entropy > 0:
            combinations = 2 ** entropy
            guesses_per_second = 10**9
            seconds = combinations / guesses_per_second

            minutes = seconds / 60
            hours = minutes / 60
            days = hours / 24
            years = days / 365

            if years >= 1:
                crack_time = f"{round(years, 2)} years"
            elif days >= 1:
                crack_time = f"{round(days, 2)} days"
            elif hours >= 1:
                crack_time = f"{round(hours, 2)} hours"
            elif minutes >= 1:
                crack_time = f"{round(minutes, 2)} minutes"
            else:
                crack_time = f"{round(seconds, 2)} seconds"

        # 🔐 BREACH CHECK SECTION
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url)

        if response.status_code == 200:
            hashes = response.text.splitlines()
            found = False

            for line in hashes:
                hash_suffix, count = line.split(":")
                if hash_suffix == suffix:
                    breach_status = f"⚠️ Password found {count} times in data breaches!"
                    found = True
                    break

            if not found:
                breach_status = "✅ Password NOT found in known breaches."
        else:
            breach_status = "Error checking breach database."

    return render_template(
            'index.html',
            strength=strength,
            entropy=entropy,
            crack_time=crack_time,
            breach_status=breach_status,
            strength_percent=strength_percent,
            suggested_password=suggested_password

        )

if __name__ == '__main__':
    app.run(debug=True)