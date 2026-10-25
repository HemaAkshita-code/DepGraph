import streamlit as st
import oracledb
import pandas as pd
import requests
from pwdlib import PasswordHash
from openai import OpenAI

st.set_page_config(page_title="DepGraph Enterprise", layout="wide")
password_hash = PasswordHash.recommended()

# --- DATABASE CONNECTION ---
def get_db():
    return oracledb.connect(user="system", password="password123", dsn="localhost:1521/FREEPDB1")

# --- 1. LOGIN SCREEN ---
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    st.title("🛡️ DepGraph Enterprise Login")
    with st.form("login_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
        
        if submit:
            try:
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT user_id, full_name, system_role, password_hash 
                    FROM users WHERE email = :email_val
                """, {"email_val": email.strip().lower()})
                user = cursor.fetchone()
                
                if user and password_hash.verify(password, user[3]):
                    st.session_state.logged_in = True
                    st.session_state.user_id = user[0]
                    st.session_state.user_name = user[1]
                    st.session_state.role = user[2]
                    st.rerun()
                else:
                    st.error("Invalid email or password.")
            except Exception as e:
                st.error(f"DB Error: {e}")

# --- 2. DASHBOARD ---
else:
    st.sidebar.title(f"👤 {st.session_state.user_name}")
    st.sidebar.write(f"Role: **{st.session_state.role}**")
    
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.rerun()

    # ==========================================
    # ADMIN VIEW
    # ==========================================
    if st.session_state.role == "ADMIN":
        tab1, tab2 = st.tabs(["🚨 Global Scan", "📋 Assign Tasks"])

        with tab1:
            st.subheader("Global Vulnerability Scan")
            if st.button("Run Full System Scan", type="primary"):
                with st.spinner("Scanning dependencies..."):
                    try:
                        from app.vulnerability_scan import execute_scan
                        found = execute_scan()
                        st.success(f"Scan complete! Found {found} vulnerabilities.")
                    except Exception as e:
                        st.error(f"Scan Error: {e}")

            st.divider()
            st.write("**Detected Vulnerabilities**")
            try:
                conn = get_db()
                df = pd.read_sql("""
                    SELECT pe.vuln_id AS "Vulnerability ID",
                           p.project_name AS "Project Name", 
                           v.advisory_code AS "CVE ID", 
                           v.severity_score AS "Severity", 
                           pe.path_text AS "Dependency Path"
                    FROM project_exposures pe
                    JOIN projects p ON pe.project_id = p.project_id
                    JOIN vulnerabilities v ON pe.vuln_id = v.vuln_id
                    ORDER BY v.severity_score DESC
                """, conn)
                st.dataframe(df, use_container_width=True)
            except Exception as e:
                st.info("No vulnerabilities found yet.")

        with tab2:
            st.subheader("Task Assignment Center")
            try:
                conn = get_db()
                tasks_query = """
                    SELECT ft.task_id AS "Task ID",
                           ft.project_id AS "Project ID",
                           ft.vuln_id AS "Vuln ID",
                           ft.team_id AS "Team ID",
                           ft.status AS "Status",
                           ft.reviewer_user_id AS "Reviewer ID"
                    FROM fix_tasks ft
                    ORDER BY ft.created_at DESC
                """
                try:
                    df_tasks = pd.read_sql(tasks_query, conn)
                    st.write("**Current Active Tasks**")
                    st.dataframe(df_tasks, use_container_width=True)
                except:
                    st.info("Fix tasks table not yet populated.")

                st.divider()
                st.write("**Assign a New Task**")
                
                vulns = pd.read_sql("""
                    SELECT 'Vuln ' || pe.vuln_id || ' - Proj ' || pe.project_id AS display_name, pe.project_id, pe.vuln_id
                    FROM project_exposures pe
                """, conn)
                
                teams_df = pd.read_sql("SELECT team_id, team_name FROM teams", conn)
                users_df = pd.read_sql("SELECT user_id, full_name FROM users WHERE system_role = 'SECURITY_ANALYST'", conn)
                
                if vulns.empty or teams_df.empty:
                    st.warning("No vulnerabilities or teams found. Run a scan first.")
                else:
                    team_dict = dict(zip(teams_df["TEAM_NAME"], teams_df["TEAM_ID"]))
                    user_dict = dict(zip(users_df["FULL_NAME"], users_df["USER_ID"]))
                    
                    with st.form("assign_form"):
                        selected_vuln = st.selectbox("Select Vulnerability / Project", vulns["DISPLAY_NAME"].tolist())
                        priority = st.selectbox("Priority", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            selected_team = st.selectbox("Assign to Team", list(team_dict.keys()))
                        with col2:
                            selected_reviewer = st.selectbox("Assign Reviewer (Analyst)", list(user_dict.keys()))
                        
                        assign_btn = st.form_submit_button("Create & Assign Task")
                        
                        if assign_btn:
                            vuln_row = vulns[vulns["DISPLAY_NAME"] == selected_vuln].iloc[0]
                            project_id = int(vuln_row["PROJECT_ID"])
                            vuln_id = int(vuln_row["VULN_ID"])
                            team_id = team_dict[selected_team]
                            reviewer_id = user_dict[selected_reviewer]
                            
                            try:
                                cursor = conn.cursor()
                                policy_df = pd.read_sql(f"SELECT policy_id FROM remediation_policies WHERE priority = '{priority}' AND is_active = 'Y'", conn)
                                policy_id = int(policy_df["POLICY_ID"].iloc[0]) if not policy_df.empty else 1
                                
                                cursor.execute("""
                                    INSERT INTO fix_tasks (
                                        project_id, vuln_id, team_id, reviewer_user_id, 
                                        created_by, policy_id, status, due_at
                                    ) VALUES (
                                        :pid, :vid, :tid, :rid, 
                                        :cbid, :pol, 'OPEN', SYSTIMESTAMP + INTERVAL '2' DAY
                                    )
                                """, {
                                    "pid": project_id, "vid": vuln_id, "tid": team_id, 
                                    "rid": reviewer_id, "cbid": st.session_state.user_id, "pol": policy_id
                                })
                                conn.commit()
                                st.success(f"✅ Task created and assigned to {selected_team}!")
                                st.rerun() 
                            except Exception as e:
                                st.error(f"Database Error: {e}")
            except Exception as e:
                st.error(f"Database error: {e}")

    # ==========================================
    # SECURITY ANALYST VIEW
    # ==========================================
    elif st.session_state.role == "SECURITY_ANALYST":
        tab1, tab2 = st.tabs(["🚨 Run Scan", "🔍 Review Fixes"])

        with tab1:
            st.subheader("Vulnerability Detection")
            if st.button("Run Full System Scan", type="primary"):
                with st.spinner("Scanning..."):
                    try:
                        from app.vulnerability_scan import execute_scan
                        found = execute_scan()
                        st.success(f"Scan complete! Found {found} vulnerabilities.")
                    except Exception as e:
                        st.error(f"Scan Error: {e}")

            st.write("**All Detected Vulnerabilities**")
            try:
                conn = get_db()
                df = pd.read_sql("""
                    SELECT pe.vuln_id AS "Vuln ID",
                           p.project_name AS "Project Name", 
                           v.advisory_code AS "CVE ID", 
                           v.severity_score AS "Severity",
                           CASE 
                               WHEN v.severity_score >= 9.0 THEN 'CRITICAL'
                               WHEN v.severity_score >= 7.0 THEN 'HIGH'
                               WHEN v.severity_score >= 4.0 THEN 'MEDIUM'
                               ELSE 'LOW'
                           END AS "Priority",
                           pe.path_text AS "Dependency Path"
                    FROM project_exposures pe
                    JOIN projects p ON pe.project_id = p.project_id
                    JOIN vulnerabilities v ON pe.vuln_id = v.vuln_id
                """, conn)
                st.dataframe(df, use_container_width=True)
            except:
                st.info("No data yet.")

        with tab2:
            st.subheader("Review Developer Fixes")
            st.write("Only tasks that developers have submitted for review will appear here.")
            
            try:
                conn = get_db()
                review_query = """
                    SELECT ft.task_id AS "Task ID",
                           ft.project_id AS "Project ID",
                           ft.vuln_id AS "Vuln ID",
                           ft.status AS "Status"
                    FROM fix_tasks ft
                    WHERE ft.reviewer_user_id = :user_val
                      AND ft.status = 'IN_REVIEW'
                """
                df_reviews = pd.read_sql(review_query, conn, params={"user_val": st.session_state.user_id})
                
                if df_reviews.empty:
                    st.info("No submitted fixes are waiting for your review.")
                else:
                    st.dataframe(df_reviews, use_container_width=True)
                    
                    task_to_review = st.selectbox("Select Task ID to Review", df_reviews["Task ID"].tolist())
                    action = st.selectbox("Action", ["Approve Fix & Mark Resolved", "Reject Fix (Needs Changes)"])
                    feedback = st.text_area("Feedback (Required for rejection)")
                    
                    if st.button("Submit Review"):
                        try:
                            new_status = "RESOLVED" if "Approve" in action else "CHANGES_REQUESTED"
                            cursor = conn.cursor()
                            cursor.execute("UPDATE fix_tasks SET status = :status_val WHERE task_id = :tid_val", {"status_val": new_status, "tid_val": task_to_review})
                            conn.commit()
                            st.success(f"Review submitted. Task marked as {new_status}.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Database Error: {e}")
            except Exception as e:
                st.error(f"Could not load reviews: {e}")

    # ==========================================
    # DEVELOPER VIEW
    # ==========================================
    else:
        st.title("👨‍💻 Developer Dashboard")
        tab1, tab2, tab3 = st.tabs(["📋 My Tasks & AI Plan", "🔗 Submit Fix", "🚨 My Vulnerabilities"])

        with tab1:
            st.subheader("My Assigned Tasks")
            try:
                conn = get_db()
                task_query = """
                    SELECT ft.task_id AS "Task ID",
                           ft.project_id AS "Project ID",
                           ft.vuln_id AS "Vuln ID",
                           ft.status AS "Status"
                    FROM fix_tasks ft
                    JOIN team_members tm ON ft.team_id = tm.team_id
                    WHERE tm.user_id = :user_val
                """
                df_my_tasks = pd.read_sql(task_query, conn, params={"user_val": st.session_state.user_id})
                
                if df_my_tasks.empty:
                    st.info("No tasks assigned to you yet.")
                else:
                    st.dataframe(df_my_tasks, use_container_width=True)
                    
                    st.divider()
                    st.write("### 🤖 AI Remediation Plan")
                    task_ids = df_my_tasks["Task ID"].tolist()
                    selected_task = st.selectbox("Select Task ID", task_ids)
                    
                    if st.button("Generate AI Plan"):
                        with st.spinner("Generating plan using AI..."):
                            try:
                                # --- DIRECT AI CALL USING GROQ ---
                                client = OpenAI(
                                    api_key="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", # <--- PASTE YOUR GROQ API KEY HERE
                                    base_url="https://api.groq.com/openai/v1"
                                )
                                
                                # Fetch details for this task to send to the AI
                                cursor = conn.cursor()
                                cursor.execute("""
                                    SELECT v.advisory_code, v.title, v.severity_score, pe.path_text
                                    FROM fix_tasks ft
                                    JOIN vulnerabilities v ON ft.vuln_id = v.vuln_id
                                    JOIN project_exposures pe ON ft.project_id = pe.project_id AND ft.vuln_id = pe.vuln_id
                                    WHERE ft.task_id = :tid_val
                                    FETCH FIRST 1 ROWS ONLY
                                """, {"tid_val": int(selected_task)})
                                vuln_data = cursor.fetchone()
                                
                                if vuln_data:
                                    cve, title, severity, path = vuln_data
                                    prompt = f"Vulnerability: {cve} - {title}. Severity: {severity}. Dependency Path: {path}. Provide a brief Vulnerability Summary, Impact Analysis, and Remediation Plan."
                                    
                                    response = client.chat.completions.create(
                                        model="openai/gpt-oss-20b",
                                        messages=[
                                            {"role": "system", "content": "You are a senior cybersecurity engineer. Provide clear, actionable advice."},
                                            {"role": "user", "content": prompt}
                                        ]
                                    )
                                    
                                    ai_plan = response.choices[0].message.content
                                    
                                    st.success("AI Plan Generated!")
                                    st.markdown(f"#### Vulnerability Summary & Plan\n{ai_plan}")
                                else:
                                    st.warning("Could not find vulnerability details for this task.")
                                    
                            except Exception as e:
                                st.error(f"AI Error: {e}")
            except Exception as e:
                st.error(f"Could not load tasks: {e}")

        with tab2:
            st.subheader("Submit a Fix for a Task")
            try:
                conn = get_db()
                my_tasks = pd.read_sql("""
                    SELECT ft.task_id, ft.project_id 
                    FROM fix_tasks ft
                    JOIN team_members tm ON ft.team_id = tm.team_id
                    WHERE tm.user_id = :user_val AND ft.status != 'RESOLVED'
                """, conn, params={"user_val": st.session_state.user_id})
                
                if not my_tasks.empty:
                    task_dict = dict(zip(my_tasks["TASK_ID"], my_tasks["PROJECT_ID"]))
                    
                    with st.form("submit_fix_form"):
                        selected_task_id = st.selectbox("Select Task ID to Fix", list(task_dict.keys()))
                        new_url = st.text_input("Updated GitHub URL", placeholder="https://github.com/...")
                        commit_sha = st.text_input("Commit SHA (40 chars)", value="a"*40)
                        
                        if st.form_submit_button("Submit Fix & Run Verification Scan"):
                            project_id = task_dict[selected_task_id]
                            
                            # 1. Update GitHub URL in DB
                            cursor = conn.cursor()
                            cursor.execute("UPDATE projects SET repo_url = :url_val WHERE project_id = :pid_val", {"url_val": new_url, "pid_val": project_id})
                            
                            # 2. Insert into fix_submissions
                            cursor.execute("""
                                INSERT INTO fix_submissions (task_id, submitted_by, commit_sha, base_sha, pull_request_url, change_summary)
                                VALUES (:tid_val, :uid_val, :sha_val, :sha2_val, :url_val, 'Fixed dependencies')
                            """, {"tid_val": selected_task_id, "uid_val": st.session_state.user_id, "sha_val": commit_sha, "sha2_val": commit_sha, "url_val": new_url})
                            conn.commit()
                            
                            st.info("GitHub link updated. Running verification scan...")
                            
                            # 3. Re-run scan
                            from app.vulnerability_scan import execute_scan
                            execute_scan()
                            
                            # 4. Check if fixed for this project
                            cursor.execute("SELECT COUNT(*) FROM project_exposures pe WHERE pe.project_id = :pid_val", {"pid_val": project_id})
                            remaining = cursor.fetchone()[0]
                            
                            if remaining == 0:
                                st.success(f"✅ Fix Verified! Project {project_id} is now secure.")
                                # 5. Set status to IN_REVIEW for the Analyst
                                cursor.execute("UPDATE fix_tasks SET status = 'IN_REVIEW' WHERE task_id = :tid_val", {"tid_val": selected_task_id})
                                conn.commit()
                            else:
                                st.error(f"❌ Still vulnerable. The scan still found {remaining} issues. (For testing, you can manually update the status to IN_REVIEW in SQL).")
            except Exception as e:
                st.error(f"Error submitting fix: {e}")

        with tab3:
            st.subheader("My Project Vulnerabilities")
            try:
                conn = get_db()
                df = pd.read_sql("""
                    SELECT pe.vuln_id AS "Vuln ID",
                           p.project_name AS "Project Name", 
                           v.advisory_code AS "CVE ID", 
                           v.severity_score AS "Severity",
                           pe.path_text AS "Dependency Path"
                    FROM project_exposures pe
                    JOIN projects p ON pe.project_id = p.project_id
                    JOIN vulnerabilities v ON pe.vuln_id = v.vuln_id
                    JOIN team_members tm ON p.owner_team_id = tm.team_id
                    WHERE tm.user_id = :user_val
                """, conn, params={"user_val": st.session_state.user_id})
                
                if df.empty:
                    st.success("🎉 No vulnerabilities found in your projects!")
                else:
                    st.dataframe(df, use_container_width=True)
            except:
                pass