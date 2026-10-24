import streamlit as st
import oracledb
import pandas as pd
from vulnerability_scan import execute_scan

st.set_page_config(page_title="DepGraph Security", layout="wide")

# --- DATABASE CONNECTION ---
def get_db():
    return oracledb.connect(user="system", password="password", dsn="localhost/XEPDB1")

# --- LOGIN SCREEN ---
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    st.title("🛡️ DepGraph Security Login")
    
    with st.form("login_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
        
        if submit:
            # TEMPORARY BYPASS FOR UI SCREENSHOTS (Replace this with real DB check later)
            if email == "admin@test.com" and password == "admin":
                st.session_state.logged_in = True
                st.session_state.user_name = "Khwaish"
                st.session_state.role = "SECURITY_ANALYST"
                st.rerun()
            else:
                st.error("Use admin@test.com / admin to view the dashboard.")

# --- DASHBOARD SCREEN ---
else:
    st.sidebar.title(f"Welcome, {st.session_state.user_name}")
    st.sidebar.write(f"Role: {st.session_state.role}")
    
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.rerun()

    st.title("🚨 Vulnerability Detection Dashboard")
    
    if st.button("Run Scan Now", type="primary"):
        with st.spinner("Scanning dependencies..."):
            try:
                # This will fail right now because DB isn't connected, but you can see the UI!
                bugs_found = execute_scan()
                st.success(f"Scan complete! Found {bugs_found} vulnerable dependencies.")
            except Exception as e:
                st.error(f"Database error: {e}")

    st.divider()
    st.subheader("Current Exposures")
    
    # Put a fake table here just for the screenshot!
    st.info("Showing placeholder data (Connect DB to see real data)")
    fake_data = pd.DataFrame({
        "Project": ["Student Portal"],
        "CVE ID": ["CVE-2023-1111"],
        "Vulnerability Title": ["Werkzeug RCE"],
        "Severity": [9.8],
        "Dependency Path": ["flask -> werkzeug-2.0.0"]
    })
    st.dataframe(fake_data, use_container_width=True)