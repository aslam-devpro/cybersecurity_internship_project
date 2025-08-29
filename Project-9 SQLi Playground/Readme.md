# 🛡️ SQLi Playground – Learn SQL Injection & Detection

This project is an educational web application that demonstrates:

* How **SQL Injection (SQLi)** attacks work
* How to prevent them using **parameterized queries**
* How a basic **SQLi detector** can identify malicious input and log attempts

⚠️ **Disclaimer:** This app is for learning purposes only. Never deploy vulnerable code in production.

---

## 🚀 Features

* 🔴 **Vulnerable Login**: Uses unsafe string concatenation in SQL queries.
* 🟢 **Safe Login**: Uses parameterized queries to prevent injection.
* 🛡️ **SQLi Detector**:

  * Compares inputs against known SQL injection payloads.
  * Logs suspicious attempts with timestamp.
  * Helps demonstrate detection & monitoring.
* 📑 **About Page**: Explains vulnerable vs. safe queries and how the detector works.

---

## 🛠️ Installation & Setup

1. **Clone the repo**

   ```bash
   git clone https://github.com/aslam-devpro/cybersecurity_internship_project/Project-9 SQLi Playground.git
   cd sqli-playground
   ```

2. **Create a virtual environment**

   ```bash
   python -m venv venv
   source venv/bin/activate   # Linux/Mac
   venv\Scripts\activate      # Windows
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Initialise the Database**

   ```bash
   python3 init_db.py
   ```
   
4. **Run the app**

   ```bash
   python3 app.py
   ```

   The app will be available at: [http://127.0.0.1:5000](http://127.0.0.1:5000)

5. **Run the detector in another terminal**

   ```bash
   python3 detector.py
   ```


---

## 🧪 Usage

1. Visit vulnerable login page.
2. Try entering normal credentials → only valid logins succeed.(eg:(alice,alicepass),(bob,bobpass))
3. Try entering injection payloads like:

   ```
   Username: ' OR '1'='1 --
   Password: anything
   ```

   → See how the **vulnerable login** is bypassed.
4. Switch to the **safe login** → Injection no longer works.
5. Check `sqli_logs.txt` → Injection attempts are logged with details.

---

## 📖 Learning Outcomes

* Difference between unsafe string concatenation vs parameterized queries.
* How attackers exploit SQL injection.
* How detection systems can log suspicious activity.
* Why **prevention** (parameterized queries) is stronger than just detection.

---

## 📜 License

This project is open-source and intended for educational use.

