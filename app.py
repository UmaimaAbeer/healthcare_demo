import logging
from flask import Flask, render_template, request, redirect, url_for, session, render_template_string

app = Flask(__name__)
app.secret_key = 'change_healthcare_breach_demo_key'

# --- MITIGATION: LOGGING (Addressing "Repudiation" & "Limited Monitoring") ---
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] AUDIT LOG: %(message)s')

# --- MOCK DATABASE (Change Healthcare = Clearinghouse/Payment Data) ---
users = {
    "admin": {"password": "password123", "mfa_enabled": False}, # VULNERABLE ACCOUNT
    "dr_smith": {"password": "secure!Pass1", "mfa_enabled": True}   # SECURE ACCOUNT
}

# Sensitive Data: "Medical and Payment Data" as per your Problem Statement
claims_data = [
    {"claim_id": "CLM-9901", "patient": "Alice Walker", "provider": "City Hospital", "status": "PAID", "amount": "$45,200"},
    {"claim_id": "CLM-9902", "patient": "Bob Jones", "provider": "West Clinic", "status": "PENDING", "amount": "$1,250"},
    {"claim_id": "CLM-9903", "patient": "Charlie Day", "provider": "Urgent Care", "status": "DENIED", "amount": "$500"},
]

@app.route('/')
def index():
    return redirect(url_for('login'))

# --- 1. PROBLEM: WEAK AUTHENTICATION (Spoofing) ---
# Mimics the "Citrix Portal" vulnerability mentioned in references
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users.get(username)

        if user and user['password'] == password:
            logging.info(f"Login Success: User '{username}'") # Mitigation for Repudiation
            
            # CHECK MFA STATUS
            if user['mfa_enabled']:
                session['temp_user'] = username
                return redirect(url_for('mfa_challenge'))
            else:
                # VULNERABILITY: No MFA allowed entry (The Breach Cause)
                session['user'] = username
                session['role'] = 'admin' # Simulating Elevation of Privilege risk
                return redirect(url_for('dashboard'))
        else:
            logging.warning(f"Failed Login Attempt: '{username}'")
            error = "Invalid Credentials"
            
    return render_template('login.html', error=error)

# --- 2. SOLUTION: MFA (Mitigation for Spoofing) ---
@app.route('/mfa', methods=['GET', 'POST'])
def mfa_challenge():
    if 'temp_user' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        code = request.form['code']
        if code == "123456": # Simulating SMS/Token check
            session['user'] = session['temp_user']
            session.pop('temp_user')
            logging.info(f"MFA Verified for: {session['user']}")
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid MFA Code"
            return render_template('mfa.html', error=error)

    return render_template('mfa.html')

# --- 3. PROBLEM: INFORMATION DISCLOSURE (Exposed Data) ---
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Displays the sensitive "Medical and Payment Data"
    return render_template('dashboard.html', user=session['user'], claims=claims_data)

# --- 4. PROBLEM: INPUT VALIDATION (XSS / Tampering) ---
# This represents the "Insecure Code" that Snyk/ZAP would find
@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # VULNERABILITY: Reflected XSS
    # If an attacker sends a link with a script, it executes in the browser.
    html_response = f"""
    <h3>Search Results for Claim ID: {query}</h3>
    <p>No specific claim found in local cache.</p>
    <a href="/dashboard">Return to Portal</a>
    """
    
    logging.info(f"Search Action: {query}")
    return render_template_string(html_response)

@app.route('/logout')
def logout():
    logging.info(f"User Logout: {session.get('user')}")
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    # "Server running" - corresponds to Availability in CIA triad
    print("Starting Change Healthcare Payment Portal Simulation...")
    app.run(debug=True, port=5000)