import streamlit as st
import pandas as pd
import numpy as np
import joblib
import shap
import sqlite3
import hashlib
import os
import json
import uuid
import struct
import html

from datetime import datetime
from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)

# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="InsureGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ============================================================
# VISUAL DESIGN
# ============================================================

st.markdown(
    """
<style>
:root {
    --navy: #172033;
    --blue: #315EFB;
    --blue-dark: #2448C8;
    --slate: #475569;
    --muted: #64748B;
    --line: #E2E8F0;
    --surface: #F8FAFC;
    --green: #15805D;
    --amber: #B86B00;
    --red: #C2393E;
}

[data-testid="stAppViewContainer"] {
    background:
        radial-gradient(circle at 8% 0%, rgba(49,94,251,.08), transparent 24rem),
        linear-gradient(180deg, #FBFCFF 0%, #FFFFFF 38%);
}

.block-container {
    max-width: 1240px;
    padding-top: 1.25rem;
    padding-bottom: 3rem;
}

#MainMenu {visibility: hidden;}
footer {visibility: hidden;}

.brand-wrap {
    padding: 6px 0 2px 0;
}
.brand-title {
    font-size: 43px;
    line-height: 1.05;
    font-weight: 800;
    letter-spacing: -1.2px;
    color: var(--navy);
    margin: 0 0 8px 0;
}
.brand-subtitle {
    font-size: 20px;
    font-weight: 650;
    color: #334155;
    margin-bottom: 6px;
}
.brand-description {
    max-width: 870px;
    font-size: 14.5px;
    line-height: 1.65;
    color: var(--muted);
}

.user-pill {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 7px;
    padding: 8px 12px;
    border: 1px solid var(--line);
    border-radius: 999px;
    background: rgba(255,255,255,.9);
    color: #334155;
    font-size: 13px;
    box-shadow: 0 3px 12px rgba(15,23,42,.04);
}

.hero-panel {
    border: 1px solid #DEE6F2;
    background: linear-gradient(135deg, #172033 0%, #21345B 63%, #315EFB 145%);
    border-radius: 18px;
    padding: 24px 26px;
    margin: 10px 0 20px 0;
    box-shadow: 0 12px 30px rgba(23,32,51,.10);
}
.hero-kicker {
    color: #BFD0FF;
    text-transform: uppercase;
    letter-spacing: 1.3px;
    font-size: 11px;
    font-weight: 800;
}
.hero-title {
    color: white;
    font-size: 26px;
    font-weight: 760;
    margin: 7px 0 6px 0;
}
.hero-copy {
    color: #DCE5F7;
    font-size: 14px;
    line-height: 1.6;
    max-width: 800px;
}

.metric-card, .info-card, .result-card, .analysis-card {
    background: rgba(255,255,255,.96);
    border: 1px solid var(--line);
    border-radius: 14px;
    box-shadow: 0 4px 16px rgba(15,23,42,.045);
}
.info-card {
    padding: 17px 19px;
    min-height: 88px;
}
.info-label, .result-label, .metric-label {
    font-size: 10.5px;
    color: var(--muted);
    font-weight: 800;
    letter-spacing: .7px;
    text-transform: uppercase;
}
.info-value {
    font-size: 19px;
    color: var(--navy);
    font-weight: 760;
    margin-top: 8px;
}
.result-card {
    padding: 20px;
    min-height: 122px;
}
.result-value {
    font-size: 28px;
    font-weight: 790;
    color: var(--navy);
    margin-top: 10px;
    line-height: 1.18;
}

.ai-summary {
    background: linear-gradient(135deg, #F3F7FF 0%, #F8FAFF 100%);
    border: 1px solid #CFDBFF;
    border-left: 5px solid var(--blue);
    border-radius: 12px;
    padding: 17px 18px;
    color: #25324A;
    line-height: 1.65;
    margin: 8px 0 16px 0;
}
.ai-summary strong { color: var(--navy); }

.factor-card {
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 14px 15px;
    margin-bottom: 10px;
    background: #FFFFFF;
}
.factor-risk { border-left: 5px solid #D84A50; }
.factor-protective { border-left: 5px solid #16906A; }
.factor-row {
    display:flex;
    align-items:flex-start;
    justify-content:space-between;
    gap:16px;
}
.factor-title {
    font-size: 14px;
    font-weight: 760;
    color: var(--navy);
}
.factor-desc {
    font-size: 12.5px;
    line-height: 1.55;
    color: var(--muted);
    margin-top: 4px;
}
.impact-badge {
    white-space: nowrap;
    padding: 5px 8px;
    border-radius: 999px;
    font-size: 10.5px;
    font-weight: 800;
}
.impact-risk { background:#FFF0F1; color:#B83239; }
.impact-protective { background:#EAF8F3; color:#0D7656; }

.governance-card {
    border: 1px solid #F1D7A8;
    background: #FFFAF0;
    border-radius: 12px;
    padding: 14px 16px;
    color: #65440D;
    line-height: 1.55;
}

.check-card {
    background: #FFFFFF;
    border: 1px solid var(--line);
    border-radius: 10px;
    padding: 11px 13px;
    margin-bottom: 8px;
    color: #334155;
    font-size: 13px;
}

.login-shell {
    max-width: 980px;
    margin: 0 auto;
}
.login-note {
    padding: 12px 14px;
    border: 1px solid #DBE5F4;
    border-radius: 10px;
    color: var(--muted);
    background: #F8FAFD;
    font-size: 12.5px;
}

.small-note {
    font-size: 11.5px;
    color: var(--muted);
    line-height: 1.55;
}

div.stButton > button,
div.stDownloadButton > button,
div[data-testid="stFormSubmitButton"] > button {
    border-radius: 9px;
    font-weight: 700;
    min-height: 42px;
}

div[data-testid="stFormSubmitButton"] > button {
    background: var(--blue);
    color: white;
    border-color: var(--blue);
}

div[data-testid="stFormSubmitButton"] > button:hover {
    background: var(--blue-dark);
    border-color: var(--blue-dark);
}

[data-baseweb="tab-list"] {
    gap: 12px;
}
[data-baseweb="tab"] {
    height: 44px;
    border-radius: 8px 8px 0 0;
    font-weight: 700;
}

[data-testid="stDataFrame"] {
    border: 1px solid var(--line);
    border-radius: 12px;
    overflow: hidden;
}
</style>
""",
    unsafe_allow_html=True,
)

DB_PATH = "insureguard.db"

# ============================================================
# GENERAL HELPERS
# ============================================================

def esc(value):
    return html.escape(str(value))


def safe_float(value):
    if value is None:
        return 0.0
    if isinstance(value, bytes):
        try:
            if len(value) == 8:
                return struct.unpack("d", value)[0]
            return float(value.decode())
        except Exception:
            return 0.0
    try:
        return float(value)
    except Exception:
        return 0.0


def json_dumps_safe(value):
    def default(obj):
        if hasattr(obj, "item"):
            return obj.item()
        return str(obj)
    return json.dumps(value, default=default)


def json_loads_safe(value, fallback):
    if value is None or value == "":
        return fallback
    try:
        return json.loads(value)
    except Exception:
        return fallback


def table_columns(cursor, table):
    cursor.execute(f"PRAGMA table_info({table})")
    return [row[1] for row in cursor.fetchall()]


def ensure_column(cursor, table, column, column_type):
    if column not in table_columns(cursor, table):
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")

# ============================================================
# PASSWORD SECURITY
# ============================================================

def create_password_hash(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 200000
    )
    return salt.hex(), password_hash.hex()


def verify_password(password, salt_hex, hash_hex):
    try:
        salt = bytes.fromhex(salt_hex)
        _, generated_hash = create_password_hash(password, salt)
        return generated_hash == hash_hex
    except Exception:
        return False

# ============================================================
# DATABASE
# ============================================================

def init_database():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT,
            password_hash TEXT,
            password_salt TEXT,
            created_at TEXT
        )
        """
    )
    for name, dtype in [
        ("email", "TEXT"),
        ("password_hash", "TEXT"),
        ("password_salt", "TEXT"),
        ("created_at", "TEXT"),
    ]:
        ensure_column(cursor, "users", name, dtype)

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS claims (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT,
            username TEXT,
            claim_reference TEXT,
            policy_reference TEXT,
            customer_reference TEXT,
            assessment_date TEXT,
            fraud_score REAL,
            risk_level TEXT,
            recommended_action TEXT,
            recommendation_text TEXT,
            risk_factors TEXT,
            claim_data TEXT,
            analysis_json TEXT
        )
        """
    )
    for name, dtype in [
        ("username", "TEXT"),
        ("risk_factors", "TEXT"),
        ("recommendation_text", "TEXT"),
        ("claim_data", "TEXT"),
        ("analysis_json", "TEXT"),
    ]:
        ensure_column(cursor, "claims", name, dtype)

    conn.commit()
    conn.close()


init_database()

# ============================================================
# USER FUNCTIONS
# ============================================================

def username_exists(username):
    conn = sqlite3.connect(DB_PATH, timeout=20)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM users WHERE LOWER(username)=LOWER(?)", (username,)
    )
    result = cursor.fetchone() is not None
    conn.close()
    return result


def email_exists(email):
    conn = sqlite3.connect(DB_PATH, timeout=20)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE LOWER(email)=LOWER(?)", (email,))
    result = cursor.fetchone() is not None
    conn.close()
    return result


def create_user(username, email, password):
    salt, password_hash = create_password_hash(password)
    created_at = datetime.now().strftime("%d %B %Y, %I:%M %p")
    conn = sqlite3.connect(DB_PATH, timeout=20)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO users (username,email,password_hash,password_salt,created_at)
        VALUES (?,?,?,?,?)
        """,
        (username, email, password_hash, salt, created_at),
    )
    conn.commit()
    conn.close()


def authenticate_user(username, password):
    conn = sqlite3.connect(DB_PATH, timeout=20)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT username,email,password_hash,password_salt
        FROM users WHERE LOWER(username)=LOWER(?)
        """,
        (username,),
    )
    result = cursor.fetchone()
    conn.close()
    if result is None:
        return None
    username_db, email, password_hash, password_salt = result
    if not password_hash or not password_salt:
        return None
    if verify_password(password, password_salt, password_hash):
        return {"username": username_db, "email": email}
    return None

# ============================================================
# CLAIM DATABASE FUNCTIONS
# ============================================================

def save_claim(
    report_id,
    username,
    claim_reference,
    policy_reference,
    customer_reference,
    assessment_date,
    fraud_score,
    risk_level,
    recommended_action,
    recommendation_text,
    risk_factors,
    claim_data,
    analysis_json,
):
    conn = sqlite3.connect(DB_PATH, timeout=20)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO claims (
            report_id,username,claim_reference,policy_reference,customer_reference,
            assessment_date,fraud_score,risk_level,recommended_action,
            recommendation_text,risk_factors,claim_data,analysis_json
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            report_id,
            username,
            claim_reference,
            policy_reference,
            customer_reference,
            assessment_date,
            float(fraud_score),
            risk_level,
            recommended_action,
            recommendation_text,
            json_dumps_safe(risk_factors),
            json_dumps_safe(claim_data),
            json_dumps_safe(analysis_json),
        ),
    )
    conn.commit()
    conn.close()


def load_user_claims(username):
    conn = sqlite3.connect(DB_PATH, timeout=20)
    df = pd.read_sql_query(
        "SELECT * FROM claims WHERE username=? ORDER BY id DESC",
        conn,
        params=(username,),
    )
    conn.close()
    if not df.empty:
        df["fraud_score"] = df["fraud_score"].apply(safe_float)
    return df


def get_claim_by_report(username, report_id):
    conn = sqlite3.connect(DB_PATH, timeout=20)
    df = pd.read_sql_query(
        """
        SELECT * FROM claims
        WHERE username=? AND report_id=?
        LIMIT 1
        """,
        conn,
        params=(username, report_id),
    )
    conn.close()
    if df.empty:
        return None
    row = df.iloc[0].copy()
    row["fraud_score"] = safe_float(row["fraud_score"])
    return row

# ============================================================
# SESSION
# ============================================================

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = None
if "email" not in st.session_state:
    st.session_state.email = None

# ============================================================
# BRAND HEADER
# ============================================================

def show_brand_header():
    st.markdown(
        """
        <div class="brand-wrap">
            <div class="brand-title">🛡️ InsureGuard AI</div>
            <div class="brand-subtitle">AI-Powered Insurance Fraud Risk Assessment</div>
            <div class="brand-description">
                Explainable machine learning for claim screening, risk prioritization and
                investigation support — designed to assist human reviewers, not replace them.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# ============================================================
# LOGIN / SIGN UP
# ============================================================

if not st.session_state.logged_in:
    st.markdown('<div class="login-shell">', unsafe_allow_html=True)
    show_brand_header()
    st.markdown(
        """
        <div class="hero-panel">
            <div class="hero-kicker">Secure Claims Intelligence</div>
            <div class="hero-title">Turn claim data into an explainable risk assessment.</div>
            <div class="hero-copy">
                Sign in to run fraud-risk assessments, review model explanations,
                reopen previous cases and download professional assessment reports.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    login_tab, signup_tab = st.tabs(["🔐 Login", "✨ Create Account"])

    with login_tab:
        _, login_col, _ = st.columns([1, 1.05, 1])
        with login_col:
            st.subheader("Welcome back")
            st.caption("Use your InsureGuard account to continue.")
            login_username = st.text_input("Username", key="login_username")
            login_password = st.text_input(
                "Password", type="password", key="login_password"
            )
            if st.button("Login", use_container_width=True, key="login_button"):
                user = authenticate_user(login_username.strip(), login_password)
                if user:
                    st.session_state.logged_in = True
                    st.session_state.username = user["username"]
                    st.session_state.email = user["email"]
                    st.rerun()
                else:
                    st.error("Incorrect username or password.")

    with signup_tab:
        _, signup_col, _ = st.columns([1, 1.05, 1])
        with signup_col:
            st.subheader("Create your account")
            st.caption("Your password is stored as a salted cryptographic hash.")
            new_username = st.text_input("Username", key="signup_username")
            new_email = st.text_input("Email Address", key="signup_email")
            new_password = st.text_input(
                "Password", type="password", key="signup_password"
            )
            confirm_password = st.text_input(
                "Confirm Password", type="password", key="signup_confirm"
            )
            if st.button(
                "Create Account", use_container_width=True, key="create_account_button"
            ):
                username = new_username.strip()
                email = new_email.strip()
                if len(username) < 3:
                    st.error("Username must contain at least 3 characters.")
                elif "@" not in email or "." not in email.split("@")[-1]:
                    st.error("Please enter a valid email address.")
                elif len(new_password) < 8:
                    st.error("Password must contain at least 8 characters.")
                elif new_password != confirm_password:
                    st.error("Passwords do not match.")
                elif username_exists(username):
                    st.error("That username already exists.")
                elif email_exists(email):
                    st.error("That email address is already registered.")
                else:
                    create_user(username, email, new_password)
                    st.success("Account created successfully. You can now log in.")

    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

# ============================================================
# LOAD MODEL + EXPLAINER (CACHED)
# ============================================================

@st.cache_resource(show_spinner=False)
def load_ai_assets():
    model = joblib.load("insureguard_model.pkl")
    model_info = joblib.load("insureguard_model_info.pkl")
    feature_names = model.named_steps["preprocessor"].get_feature_names_out()
    explainer = shap.TreeExplainer(model.named_steps["classifier"])
    return model, model_info, feature_names, explainer


try:
    model, model_info, feature_names, explainer = load_ai_assets()
except Exception as exc:
    st.error("InsureGuard could not load the trained AI model files.")
    st.exception(exc)
    st.stop()

categorical_columns = model_info["categorical_columns"]
numerical_columns = model_info["numerical_columns"]
category_options = {
    key: list(values) for key, values in model_info["category_options"].items()
}
medium_threshold = model_info.get("medium_risk_threshold", 0.40)
high_threshold = model_info.get("high_risk_threshold", 0.65)

for column in ["DayOfWeekClaimed", "MonthClaimed"]:
    if column in category_options:
        category_options[column] = [
            value for value in category_options[column] if str(value) != "0"
        ]

# ============================================================
# FIELD LABELS + GROUPS
# ============================================================

field_labels = {
    "Month": "Accident Month",
    "WeekOfMonth": "Accident Week of Month",
    "DayOfWeek": "Accident Day",
    "Make": "Vehicle Make",
    "AccidentArea": "Accident Area",
    "DayOfWeekClaimed": "Claim Report Day",
    "MonthClaimed": "Claim Month",
    "WeekOfMonthClaimed": "Claim Week of Month",
    "Sex": "Policy Holder Gender",
    "MaritalStatus": "Marital Status",
    "Age": "Policy Holder Age",
    "Fault": "Fault",
    "PolicyType": "Policy Type",
    "VehicleCategory": "Vehicle Category",
    "VehiclePrice": "Vehicle Price Range",
    "RepNumber": "Representative Number",
    "Deductible": "Deductible Amount",
    "DriverRating": "Driver Rating",
    "Days_Policy_Accident": "Policy Age at Accident",
    "Days_Policy_Claim": "Policy Age at Claim",
    "PastNumberOfClaims": "Previous Claims",
    "AgeOfVehicle": "Vehicle Age",
    "AgeOfPolicyHolder": "Policy Holder Age Group",
    "PoliceReportFiled": "Police Report Filed",
    "WitnessPresent": "Witness Present",
    "AgentType": "Agent Type",
    "NumberOfSuppliments": "Number of Supplements",
    "AddressChange_Claim": "Time Since Address Change",
    "NumberOfCars": "Number of Vehicles",
    "Year": "Claim Year",
    "BasePolicy": "Base Policy",
}

policyholder_fields = [
    "Sex",
    "MaritalStatus",
    "Age",
    "AgeOfPolicyHolder",
    "AddressChange_Claim",
]
vehicle_fields = [
    "Make",
    "VehicleCategory",
    "VehiclePrice",
    "AgeOfVehicle",
    "NumberOfCars",
    "DriverRating",
]
accident_fields = [
    "Month",
    "WeekOfMonth",
    "DayOfWeek",
    "AccidentArea",
    "Fault",
    "PoliceReportFiled",
    "WitnessPresent",
]
claim_policy_fields = [
    "DayOfWeekClaimed",
    "MonthClaimed",
    "WeekOfMonthClaimed",
    "PolicyType",
    "BasePolicy",
    "Days_Policy_Accident",
    "Days_Policy_Claim",
    "PastNumberOfClaims",
    "Deductible",
    "AgentType",
    "RepNumber",
    "NumberOfSuppliments",
    "Year",
]

SENSITIVE_FIELDS = {"Sex", "MaritalStatus", "Age", "AgeOfPolicyHolder"}

# ============================================================
# FORM FIELD RENDERER
# ============================================================

def render_field(column, inputs):
    label = field_labels.get(column, column)
    if column in categorical_columns:
        options = category_options.get(column, [])
        if not options:
            options = [""]
        inputs[column] = st.selectbox(label, options, key=f"field_{column}")
        return

    if column == "Age":
        inputs[column] = st.number_input(
            label, min_value=16, max_value=100, value=35, step=1, key=f"field_{column}"
        )
    elif column == "DriverRating":
        inputs[column] = st.number_input(
            label, min_value=1, max_value=4, value=2, step=1, key=f"field_{column}"
        )
    elif column == "Deductible":
        inputs[column] = st.number_input(
            label, min_value=0, value=400, step=100, key=f"field_{column}"
        )
    elif column in ["WeekOfMonth", "WeekOfMonthClaimed"]:
        inputs[column] = st.number_input(
            label, min_value=1, max_value=5, value=1, step=1, key=f"field_{column}"
        )
    elif column == "RepNumber":
        inputs[column] = st.number_input(
            label, min_value=1, max_value=16, value=1, step=1, key=f"field_{column}"
        )
    elif column == "Year":
        inputs[column] = st.number_input(
            label, min_value=1990, max_value=2035, value=1994, step=1, key=f"field_{column}"
        )
    else:
        inputs[column] = st.number_input(label, value=1, step=1, key=f"field_{column}")

# ============================================================
# EXPLAINABLE AI ENGINE
# ============================================================

def encoded_feature_to_original(encoded_name):
    if encoded_name.startswith("num__"):
        return encoded_name.replace("num__", "", 1)
    if encoded_name.startswith("cat__"):
        remainder = encoded_name.replace("cat__", "", 1)
        for column in sorted(categorical_columns, key=len, reverse=True):
            if remainder == column or remainder.startswith(column + "_"):
                return column
    clean = encoded_name.replace("num__", "").replace("cat__", "")
    for column in sorted(field_labels.keys(), key=len, reverse=True):
        if clean == column or clean.startswith(column + "_"):
            return column
    return clean


def get_shap_vector(transformed_claim):
    values = explainer.shap_values(transformed_claim)
    arr = np.asarray(values)

    # Typical binary XGBoost TreeExplainer: (1, n_features)
    if arr.ndim == 2 and arr.shape[0] == 1:
        return arr[0].astype(float)

    # Some versions return (1, n_features, 2) or (2, 1, n_features)
    if arr.ndim == 3:
        if arr.shape[0] == 1 and arr.shape[-1] == 2:
            return arr[0, :, 1].astype(float)
        if arr.shape[0] == 2 and arr.shape[1] == 1:
            return arr[1, 0, :].astype(float)

    # List-of-arrays style for classes
    if isinstance(values, list) and len(values) > 1:
        candidate = np.asarray(values[1])
        return candidate[0].astype(float) if candidate.ndim == 2 else candidate.astype(float)

    flat = arr.reshape(-1)
    if len(flat) >= len(feature_names):
        return flat[: len(feature_names)].astype(float)
    raise ValueError("Unexpected SHAP output shape")


def impact_level(share):
    if share >= 18:
        return "High impact"
    if share >= 8:
        return "Moderate impact"
    return "Lower impact"


def factor_explanation(field, actual_value, direction):
    label = field_labels.get(field, field)
    direction_text = "increased" if direction == "risk" else "reduced"
    return (
        f"For this specific claim, the model's SHAP explanation indicates that "
        f"{label.lower()} = {actual_value} {direction_text} the fraud-risk prediction "
        f"relative to the model's local baseline. This is an association learned from "
        f"historical patterns, not proof of fraud or causation."
    )


def build_investigation_plan(risk_drivers):
    action_map = {
        "Fault": "Cross-check liability statements, accident narrative and supporting evidence for consistency.",
        "PastNumberOfClaims": "Review prior claim dates, outcomes, counterparties and any repeated loss patterns.",
        "PoliceReportFiled": "Validate the police report details or document why a report was not filed.",
        "WitnessPresent": "Seek independent corroboration such as witness statements, third-party records or scene evidence.",
        "AddressChange_Claim": "Verify identity, contact information and the timing of any address change against policy records.",
        "Days_Policy_Accident": "Review policy inception timing relative to the accident and confirm coverage was active.",
        "Days_Policy_Claim": "Check the reporting timeline and validate the reason for any unusual claim-reporting delay.",
        "VehiclePrice": "Validate vehicle valuation using policy records, market evidence and repair/replacement documentation.",
        "AgeOfVehicle": "Confirm vehicle age, condition and valuation are consistent with the submitted claim evidence.",
        "AgentType": "Review the originating sales/agent channel and relevant policy documentation for consistency.",
        "NumberOfSuppliments": "Review supplementary submissions and estimate revisions for consistency and supporting evidence.",
        "Deductible": "Confirm deductible terms, payment responsibility and policy documentation.",
        "Make": "Verify vehicle identity, registration, VIN and declared make against claim documents.",
        "VehicleCategory": "Confirm the insured vehicle category matches registration and policy records.",
        "AccidentArea": "Validate incident location using available reports, timestamps and supporting evidence.",
        "NumberOfCars": "Reconcile all involved vehicles, parties and supporting accident documentation.",
        "PolicyType": "Confirm the claimed loss is consistent with the selected policy type and coverage conditions.",
        "BasePolicy": "Confirm base-policy coverage and exclusions relevant to the reported loss.",
        "Month": "Validate the incident date and timeline against all supporting documents.",
        "DayOfWeek": "Validate the incident date and timeline against all supporting documents.",
        "MonthClaimed": "Compare claim submission timing with the reported incident timeline.",
        "DayOfWeekClaimed": "Compare claim submission timing with the reported incident timeline.",
        "DriverRating": "Review the available driver-risk information together with the incident evidence; do not treat this factor alone as proof of fraud.",
    }

    actions = []
    for item in risk_drivers:
        field = item["field"]
        if field in SENSITIVE_FIELDS:
            continue
        action = action_map.get(field)
        if action and action not in actions:
            actions.append(action)
        if len(actions) >= 5:
            break

    if not actions:
        actions = [
            "Verify the claim narrative against policy records and supporting documentation.",
            "Confirm material dates, parties, vehicle information and submitted evidence are internally consistent.",
        ]
    return actions


def build_ai_analysis(claim_df, score, risk_level):
    transformed_claim = model.named_steps["preprocessor"].transform(claim_df)
    shap_vector = get_shap_vector(transformed_claim)

    if len(shap_vector) != len(feature_names):
        usable = min(len(shap_vector), len(feature_names))
        shap_vector = shap_vector[:usable]
        names = list(feature_names[:usable])
    else:
        names = list(feature_names)

    aggregated = {}
    for encoded_name, shap_value in zip(names, shap_vector):
        original = encoded_feature_to_original(str(encoded_name))
        aggregated[original] = aggregated.get(original, 0.0) + float(shap_value)

    total_abs = sum(abs(v) for v in aggregated.values()) or 1.0
    rows = []
    for field, contribution in aggregated.items():
        actual_value = claim_df.iloc[0][field] if field in claim_df.columns else "N/A"
        share = abs(contribution) / total_abs * 100
        rows.append(
            {
                "field": field,
                "label": field_labels.get(field, field),
                "value": str(actual_value),
                "contribution": float(contribution),
                "share": float(share),
                "impact": impact_level(share),
                "sensitive": field in SENSITIVE_FIELDS,
            }
        )

    risk_drivers = sorted(
        [r for r in rows if r["contribution"] > 0],
        key=lambda x: x["contribution"],
        reverse=True,
    )[:5]
    protective_factors = sorted(
        [r for r in rows if r["contribution"] < 0],
        key=lambda x: x["contribution"],
    )[:4]

    displayed_abs = sum(abs(x["contribution"]) for x in risk_drivers + protective_factors)
    explanation_coverage = min(displayed_abs / total_abs * 100, 100.0)

    sensitive_abs = sum(abs(r["contribution"]) for r in rows if r["sensitive"])
    sensitive_share = min(sensitive_abs / total_abs * 100, 100.0)

    non_sensitive_risk = [r for r in risk_drivers if not r["sensitive"]]
    top_names = [f"{r['label']} ({r['value']})" for r in non_sensitive_risk[:3]]
    protective_names = [f"{r['label']} ({r['value']})" for r in protective_factors[:2] if not r["sensitive"]]

    if risk_level == "HIGH":
        opening = (
            f"InsureGuard estimates a {score:.1f}% fraud-risk probability, placing this claim in the HIGH-risk review tier."
        )
    elif risk_level == "MEDIUM":
        opening = (
            f"InsureGuard estimates a {score:.1f}% fraud-risk probability, placing this claim in the MEDIUM-risk verification tier."
        )
    else:
        opening = (
            f"InsureGuard estimates a {score:.1f}% fraud-risk probability, placing this claim in the LOW-risk processing tier."
        )

    if top_names:
        driver_text = " The strongest non-sensitive upward drivers were " + ", ".join(top_names) + "."
    else:
        driver_text = " No dominant non-sensitive upward driver was identified among the displayed factors."

    if protective_names:
        protective_text = " Factors that pushed the prediction lower included " + ", ".join(protective_names) + "."
    else:
        protective_text = " No strong risk-reducing factor was identified among the displayed factors."

    summary = opening + driver_text + protective_text
    investigation_plan = build_investigation_plan(risk_drivers)

    return {
        "summary": summary,
        "risk_drivers": risk_drivers,
        "protective_factors": protective_factors,
        "explanation_coverage": explanation_coverage,
        "sensitive_share": sensitive_share,
        "investigation_plan": investigation_plan,
        "all_aggregated_factors": rows,
    }

# ============================================================
# RISK LOGIC
# ============================================================

def classify_risk(probability):
    if probability >= high_threshold:
        return (
            "HIGH",
            "Manual Investigation Recommended",
            "This claim displays a high model-estimated fraud-risk score. A trained claims reviewer should perform enhanced verification before approval or settlement, focusing on the evidence and non-sensitive risk drivers highlighted by the model.",
        )
    if probability >= medium_threshold:
        return (
            "MEDIUM",
            "Additional Verification Recommended",
            "The model identified a moderate fraud-risk profile. Additional documentation checks and targeted verification are recommended before normal processing continues.",
        )
    return (
        "LOW",
        "Standard Processing May Continue",
        "The claim currently shows a relatively low model-estimated fraud-risk score. Standard processing may continue subject to normal insurance controls and human review requirements.",
    )

# ============================================================
# PDF
# ============================================================

PDF_NAVY = colors.HexColor("#172033")
PDF_BLUE = colors.HexColor("#315EFB")
PDF_LIGHT = colors.HexColor("#F7F9FC")
PDF_LINE = colors.HexColor("#E1E7EF")
PDF_TEXT = colors.HexColor("#263445")
PDF_MUTED = colors.HexColor("#667085")
PDF_GREEN = colors.HexColor("#15805D")
PDF_GREEN_BG = colors.HexColor("#EAF8F3")
PDF_AMBER = colors.HexColor("#B86B00")
PDF_AMBER_BG = colors.HexColor("#FFF7E7")
PDF_RED = colors.HexColor("#C2393E")
PDF_RED_BG = colors.HexColor("#FFF0F1")


def pdf_header_footer(canvas, doc):
    canvas.saveState()
    width, height = A4
    canvas.setFillColor(PDF_NAVY)
    canvas.rect(0, height - 18 * mm, width, 18 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(15 * mm, height - 11 * mm, "INSUREGUARD AI")
    canvas.setFillColor(colors.HexColor("#C9D5EA"))
    canvas.setFont("Helvetica", 7.5)
    canvas.drawRightString(width - 15 * mm, height - 11 * mm, "EXPLAINABLE FRAUD-RISK ASSESSMENT")
    canvas.setStrokeColor(PDF_LINE)
    canvas.line(15 * mm, 14 * mm, width - 15 * mm, 14 * mm)
    canvas.setFillColor(PDF_MUTED)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(15 * mm, 9 * mm, "Confidential · Decision Support Only")
    canvas.drawRightString(width - 15 * mm, 9 * mm, f"Page {doc.page}")
    canvas.restoreState()


def pdf_table(rows, widths=(55 * mm, 115 * mm)):
    table = Table(rows, colWidths=list(widths))
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), PDF_LIGHT),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TEXTCOLOR", (0, 0), (-1, -1), PDF_TEXT),
                ("BOX", (0, 0), (-1, -1), 0.5, PDF_LINE),
                ("INNERGRID", (0, 0), (-1, -1), 0.35, PDF_LINE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return table


def create_pdf_report(
    report_id,
    claim_reference,
    policy_reference,
    customer_reference,
    assessment_date,
    score,
    risk_level,
    action_title,
    recommendation,
    analysis,
    claim_data,
):
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=27 * mm,
        bottomMargin=20 * mm,
        title=f"InsureGuard AI Assessment {report_id}",
        author="InsureGuard AI",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CustomTitle", parent=styles["Title"], fontSize=22, leading=26, textColor=PDF_NAVY, spaceAfter=5
    )
    subtitle_style = ParagraphStyle(
        "CustomSubtitle", parent=styles["BodyText"], fontSize=9.5, leading=14, textColor=PDF_MUTED, spaceAfter=12
    )
    section_style = ParagraphStyle(
        "Section", parent=styles["Heading2"], fontSize=12.5, textColor=PDF_NAVY, spaceBefore=10, spaceAfter=7
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["BodyText"], fontSize=8.8, leading=13, textColor=PDF_TEXT
    )
    small_style = ParagraphStyle(
        "Small", parent=styles["BodyText"], fontSize=7.6, leading=11, textColor=PDF_MUTED
    )

    story = [
        Paragraph("Insurance Fraud Risk Assessment", title_style),
        Paragraph("XGBoost prediction with SHAP-based local explainability and governance indicators", subtitle_style),
        Paragraph("Case Information", section_style),
        pdf_table(
            [
                ["Report ID", report_id],
                ["Claim Reference", claim_reference or "Not provided"],
                ["Policy Reference", policy_reference or "Not provided"],
                ["Customer Reference", customer_reference or "Not provided"],
                ["Assessment Date", assessment_date],
                ["Account", st.session_state.username],
                ["Model", "XGBoost Classifier + SHAP Explainability"],
            ]
        ),
        Spacer(1, 12),
    ]

    if risk_level == "HIGH":
        risk_color, risk_bg = PDF_RED, PDF_RED_BG
    elif risk_level == "MEDIUM":
        risk_color, risk_bg = PDF_AMBER, PDF_AMBER_BG
    else:
        risk_color, risk_bg = PDF_GREEN, PDF_GREEN_BG

    summary_table = Table(
        [
            ["FRAUD RISK SCORE", "RISK LEVEL", "RECOMMENDED ACTION"],
            [f"{score:.2f}%", risk_level, action_title],
        ],
        colWidths=[45 * mm, 35 * mm, 90 * mm],
    )
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF4FF")),
                ("BACKGROUND", (1, 1), (1, 1), risk_bg),
                ("TEXTCOLOR", (1, 1), (1, 1), risk_color),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOX", (0, 0), (-1, -1), 0.6, PDF_LINE),
                ("INNERGRID", (0, 0), (-1, -1), 0.35, PDF_LINE),
                ("TOPPADDING", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
            ]
        )
    )
    story.extend([
        Paragraph("Risk Assessment Summary", section_style),
        summary_table,
        Spacer(1, 10),
        Paragraph("AI Assessment Narrative", section_style),
        Paragraph(analysis.get("summary", ""), body_style),
        Spacer(1, 8),
    ])

    driver_rows = [["FACTOR", "VALUE", "LOCAL SHARE", "IMPACT"]]
    for item in analysis.get("risk_drivers", [])[:5]:
        driver_rows.append(
            [item["label"], item["value"], f"{item['share']:.1f}%", item["impact"]]
        )
    if len(driver_rows) == 1:
        driver_rows.append(["No dominant upward driver", "—", "—", "—"])
    driver_table = Table(driver_rows, colWidths=[55 * mm, 50 * mm, 28 * mm, 37 * mm])
    driver_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PDF_RED_BG),
                ("TEXTCOLOR", (0, 0), (-1, 0), PDF_RED),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("BOX", (0, 0), (-1, -1), 0.5, PDF_LINE),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, PDF_LINE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.extend([
        Paragraph("Top Risk Drivers — SHAP", section_style),
        driver_table,
        Spacer(1, 10),
    ])

    protective_rows = [["FACTOR", "VALUE", "LOCAL SHARE", "IMPACT"]]
    for item in analysis.get("protective_factors", [])[:4]:
        protective_rows.append(
            [item["label"], item["value"], f"{item['share']:.1f}%", item["impact"]]
        )
    if len(protective_rows) == 1:
        protective_rows.append(["No dominant risk-reducing factor", "—", "—", "—"])
    protective_table = Table(protective_rows, colWidths=[55 * mm, 50 * mm, 28 * mm, 37 * mm])
    protective_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PDF_GREEN_BG),
                ("TEXTCOLOR", (0, 0), (-1, 0), PDF_GREEN),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("BOX", (0, 0), (-1, -1), 0.5, PDF_LINE),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, PDF_LINE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.extend([
        Paragraph("Risk-Reducing Factors — SHAP", section_style),
        protective_table,
        Spacer(1, 10),
        Paragraph("Investigation Recommendation", section_style),
        Paragraph(recommendation, body_style),
        Spacer(1, 8),
        Paragraph("AI-Assisted Investigation Checklist", section_style),
    ])
    for i, action in enumerate(analysis.get("investigation_plan", []), start=1):
        story.append(Paragraph(f"{i}. {action}", body_style))
        story.append(Spacer(1, 3))

    story.append(PageBreak())
    story.extend([
        Paragraph("Explainability, Fairness & Governance", title_style),
        Paragraph("Model transparency indicators for responsible use", subtitle_style),
        pdf_table(
            [
                ["Explanation Coverage", f"{analysis.get('explanation_coverage', 0):.1f}% of local absolute SHAP contribution represented by displayed factors"],
                ["Sensitive-Feature Influence", f"{analysis.get('sensitive_share', 0):.1f}% of local absolute SHAP contribution"],
                ["Human Review", "Required — model output is decision support only"],
                ["Risk Thresholds", f"Medium ≥ {medium_threshold*100:.0f}% · High ≥ {high_threshold*100:.0f}%"],
            ]
        ),
        Spacer(1, 12),
        Paragraph("Fairness Guardrail", section_style),
        Paragraph(
            "The model may contain demographic or age-related variables from the historical dataset. "
            "InsureGuard surfaces their local influence as a governance signal, but these attributes "
            "should not be used as standalone reasons for investigation, denial or other adverse action. "
            "A production system should perform formal fairness testing, legal review and feature-governance controls.",
            body_style,
        ),
        Spacer(1, 10),
        Paragraph("Methodology", section_style),
        Paragraph(
            "The fraud-risk probability is produced by a trained XGBoost classifier. SHAP values are then "
            "calculated for the individual claim and aggregated back to the original input fields. Positive "
            "SHAP contribution moves the prediction toward the fraud-risk class; negative contribution moves "
            "it away. Local contribution share is based on the absolute SHAP magnitude for this claim and is "
            "not a causal effect or population-level importance score.",
            body_style,
        ),
        Spacer(1, 10),
        Paragraph("Important Limitations", section_style),
    ])
    for limitation in [
        "Historical data can contain bias, outdated patterns and sampling limitations.",
        "A high score does not prove fraud, and a low score does not guarantee a legitimate claim.",
        "False positives and false negatives are possible.",
        "Predictions and explanations should be combined with documentary evidence and trained human review.",
        "A production model should be monitored for drift, calibration, fairness and changing fraud patterns.",
    ]:
        story.append(Paragraph(f"• {limitation}", body_style))
        story.append(Spacer(1, 3))

    doc.build(story, onFirstPage=pdf_header_footer, onLaterPages=pdf_header_footer)
    buffer.seek(0)
    return buffer

# ============================================================
# ASSESSMENT DISPLAY
# ============================================================

def render_factor_card(item, direction):
    is_risk = direction == "risk"
    card_class = "factor-risk" if is_risk else "factor-protective"
    badge_class = "impact-risk" if is_risk else "impact-protective"
    arrow = "↑ Risk driver" if is_risk else "↓ Risk reducer"
    desc = factor_explanation(item["field"], item["value"], direction)
    sensitive_note = " · Governance-sensitive field" if item.get("sensitive") else ""
    st.markdown(
        f"""
        <div class="factor-card {card_class}">
            <div class="factor-row">
                <div>
                    <div class="factor-title">{esc(item['label'])}: {esc(item['value'])}</div>
                    <div class="factor-desc">{esc(desc)}</div>
                </div>
                <div class="impact-badge {badge_class}">{arrow} · {item['share']:.1f}% · {esc(item['impact'])}{esc(sensitive_note)}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def display_assessment(
    score,
    risk_level,
    action_title,
    recommendation,
    analysis,
    report_id,
    claim_reference,
    policy_reference,
    customer_reference,
    assessment_date,
    claim_data,
    source="main",
):
    icon = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟢"}.get(risk_level, "🔵")

    st.markdown("### AI Risk Assessment")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(
            f'<div class="result-card"><div class="result-label">Fraud Risk Score</div><div class="result-value">{score:.2f}%</div></div>',
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f'<div class="result-card"><div class="result-label">Risk Classification</div><div class="result-value">{icon} {esc(risk_level)}</div></div>',
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f'<div class="result-card"><div class="result-label">Recommended Action</div><div class="result-value" style="font-size:17px">{esc(action_title)}</div></div>',
            unsafe_allow_html=True,
        )

    st.write("#### Risk Indicator")
    st.progress(max(0, min(int(round(score)), 100)))
    st.markdown(
        '<div class="small-note">Model-estimated fraud-risk probability. This is a screening signal, not proof of fraud.</div>',
        unsafe_allow_html=True,
    )

    st.markdown("### ✨ AI Assessment Summary")
    st.markdown(
        f'<div class="ai-summary"><strong>Model interpretation:</strong> {esc(analysis.get("summary", ""))}</div>',
        unsafe_allow_html=True,
    )

    g1, g2, g3 = st.columns(3)
    with g1:
        st.metric("Explanation Coverage", f"{analysis.get('explanation_coverage', 0):.1f}%")
    with g2:
        st.metric("Sensitive-Feature Influence", f"{analysis.get('sensitive_share', 0):.1f}%")
    with g3:
        st.metric("Human Review", "Required")

    st.markdown("### 🧠 Why the AI produced this result")
    st.caption(
        "SHAP values are aggregated back to the original claim fields. The percentages below are each field's share of the local absolute SHAP contribution for this claim."
    )

    left, right = st.columns(2)
    with left:
        st.markdown("#### Risk Drivers ↑")
        drivers = analysis.get("risk_drivers", [])
        if drivers:
            for item in drivers:
                render_factor_card(item, "risk")
        else:
            st.info("No dominant upward risk driver was identified.")

    with right:
        st.markdown("#### Risk-Reducing Factors ↓")
        protective = analysis.get("protective_factors", [])
        if protective:
            for item in protective:
                render_factor_card(item, "protective")
        else:
            st.info("No dominant risk-reducing factor was identified.")

    if analysis.get("sensitive_share", 0) > 0:
        st.markdown("#### ⚖️ Fairness & Governance Monitor")
        st.markdown(
            f"""
            <div class="governance-card">
                <strong>Sensitive-feature local influence: {analysis.get('sensitive_share',0):.1f}%.</strong><br>
                The historical model includes age/demographic-related fields. InsureGuard does not use those
                fields as standalone investigation recommendations. This signal is surfaced so a reviewer can
                identify potential fairness risk. A real production deployment should perform formal fairness,
                legal and feature-governance review.
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("### 🔎 AI-Assisted Investigation Plan")
    st.caption("Targeted verification steps generated from the strongest non-sensitive model drivers.")
    for i, action in enumerate(analysis.get("investigation_plan", []), start=1):
        st.markdown(
            f'<div class="check-card"><strong>{i}.</strong> {esc(action)}</div>',
            unsafe_allow_html=True,
        )

    st.markdown("### Recommended Action")
    if risk_level == "HIGH":
        st.error(recommendation)
    elif risk_level == "MEDIUM":
        st.warning(recommendation)
    else:
        st.success(recommendation)

    with st.expander("Assessment details", expanded=False):
        d1, d2 = st.columns(2)
        with d1:
            st.write("**Report ID:**", report_id)
            st.write("**Claim Reference:**", claim_reference or "Not provided")
            st.write("**Policy Reference:**", policy_reference or "Not provided")
        with d2:
            st.write("**Customer Reference:**", customer_reference or "Not provided")
            st.write("**Assessment Date:**", assessment_date)
            st.write("**Model:**", "XGBoost + SHAP")

    pdf = create_pdf_report(
        report_id=report_id,
        claim_reference=claim_reference,
        policy_reference=policy_reference,
        customer_reference=customer_reference,
        assessment_date=assessment_date,
        score=score,
        risk_level=risk_level,
        action_title=action_title,
        recommendation=recommendation,
        analysis=analysis,
        claim_data=claim_data,
    )
    st.download_button(
        "⬇️ Download Professional PDF Assessment",
        data=pdf,
        file_name=f"InsureGuard_{claim_reference if claim_reference else report_id}_Assessment.pdf",
        mime="application/pdf",
        use_container_width=True,
        key=f"download_{source}_{report_id}",
    )

# ============================================================
# LOGGED-IN TOP BAR
# ============================================================

space, user_col, logout_col = st.columns([6.0, 1.55, 0.85])
with user_col:
    st.markdown(
        f'<div class="user-pill">👤 <strong>{esc(st.session_state.username)}</strong></div>',
        unsafe_allow_html=True,
    )
with logout_col:
    if st.button("Log out", key="top_logout", use_container_width=True):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.session_state.email = None
        st.rerun()

show_brand_header()

st.markdown(
    """
    <div class="hero-panel">
        <div class="hero-kicker">Explainable Claims Intelligence</div>
        <div class="hero-title">From claim data to an auditable AI risk assessment.</div>
        <div class="hero-copy">
            InsureGuard combines XGBoost prediction with SHAP explainability, fairness monitoring,
            AI-assisted investigation guidance and case history — while keeping final decisions with human reviewers.
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ============================================================
# MAIN TABS
# ============================================================

tab_new, tab_history = st.tabs(["🔍 New Assessment", "📚 Previous Claims"])

# ============================================================
# NEW ASSESSMENT
# ============================================================

with tab_new:
    info1, info2, info3, info4 = st.columns(4)
    with info1:
        st.markdown('<div class="info-card"><div class="info-label">Prediction Model</div><div class="info-value">XGBoost</div></div>', unsafe_allow_html=True)
    with info2:
        st.markdown('<div class="info-card"><div class="info-label">Explainability</div><div class="info-value">SHAP</div></div>', unsafe_allow_html=True)
    with info3:
        st.markdown('<div class="info-card"><div class="info-label">AI Governance</div><div class="info-value">Fairness Monitor</div></div>', unsafe_allow_html=True)
    with info4:
        st.markdown('<div class="info-card"><div class="info-label">Decision Mode</div><div class="info-value">Human-in-the-Loop</div></div>', unsafe_allow_html=True)

    st.divider()
    st.header("New Claim Assessment")
    st.info(
        "InsureGuard is an AI decision-support system. It prioritizes claims for review and explains model behavior; it does not independently determine fraud or make final claim decisions."
    )

    st.subheader("📋 Assessment Information")
    r1, r2, r3 = st.columns(3)
    with r1:
        claim_reference = st.text_input("Claim Reference", placeholder="CLM-2026-001")
    with r2:
        policy_reference = st.text_input("Policy Reference", placeholder="POL-001245")
    with r3:
        customer_reference = st.text_input("Customer Reference", placeholder="CUST-1001")
    st.caption("Reference fields are stored with the case but are not used by the ML model.")
    st.divider()

    inputs = {}
    with st.form("claim_form"):
        st.subheader("👤 Policy Holder Details")
        left, right = st.columns(2)
        for i, field in enumerate(policyholder_fields):
            with (left if i % 2 == 0 else right):
                render_field(field, inputs)

        st.divider()
        st.subheader("🚗 Vehicle Details")
        left, right = st.columns(2)
        for i, field in enumerate(vehicle_fields):
            with (left if i % 2 == 0 else right):
                render_field(field, inputs)

        st.divider()
        st.subheader("⚠️ Accident Details")
        left, right = st.columns(2)
        for i, field in enumerate(accident_fields):
            with (left if i % 2 == 0 else right):
                render_field(field, inputs)

        st.divider()
        st.subheader("📄 Claim & Policy Details")
        left, right = st.columns(2)
        for i, field in enumerate(claim_policy_fields):
            with (left if i % 2 == 0 else right):
                render_field(field, inputs)

        st.divider()
        analyze = st.form_submit_button("✨ Analyze Claim with InsureGuard AI", use_container_width=True)

    if analyze:
        try:
            with st.spinner("InsureGuard AI is analyzing claim risk and generating an explanation..."):
                claim_df = pd.DataFrame([inputs])
                claim_df = claim_df[categorical_columns + numerical_columns]
                probability = float(model.predict_proba(claim_df)[0][1])
                score = probability * 100
                risk_level, action_title, recommendation = classify_risk(probability)
                analysis = build_ai_analysis(claim_df, score, risk_level)

                assessment_date = datetime.now().strftime("%d %B %Y, %I:%M %p")
                report_id = (
                    "IGA-"
                    + datetime.now().strftime("%Y%m%d")
                    + "-"
                    + uuid.uuid4().hex[:6].upper()
                )
                claim_data = claim_df.iloc[0].to_dict()

                # Backward-compatible simplified factor list
                factor_strings = [
                    f"{x['label']}: {x['value']} ({x['share']:.1f}% local SHAP share)"
                    for x in analysis.get("risk_drivers", [])
                ]

                save_claim(
                    report_id=report_id,
                    username=st.session_state.username,
                    claim_reference=claim_reference,
                    policy_reference=policy_reference,
                    customer_reference=customer_reference,
                    assessment_date=assessment_date,
                    fraud_score=score,
                    risk_level=risk_level,
                    recommended_action=action_title,
                    recommendation_text=recommendation,
                    risk_factors=factor_strings,
                    claim_data=claim_data,
                    analysis_json=analysis,
                )

            st.divider()
            display_assessment(
                score=score,
                risk_level=risk_level,
                action_title=action_title,
                recommendation=recommendation,
                analysis=analysis,
                report_id=report_id,
                claim_reference=claim_reference,
                policy_reference=policy_reference,
                customer_reference=customer_reference,
                assessment_date=assessment_date,
                claim_data=claim_data,
                source="new",
            )
        except Exception as exc:
            st.error("The claim could not be analyzed. Please review the entered values and try again.")
            with st.expander("Technical details"):
                st.exception(exc)

# ============================================================
# PREVIOUS CLAIMS
# ============================================================

with tab_history:
    st.header("Previous Claims")
    st.caption("Search your saved assessments. A full AI review opens only after you explicitly select a case.")

    claims_df = load_user_claims(st.session_state.username)

    if claims_df.empty:
        st.info("You have not analyzed any claims yet.")
    else:
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Total Claims", len(claims_df))
        with c2:
            st.metric("High Risk", int((claims_df["risk_level"] == "HIGH").sum()))
        with c3:
            st.metric("Medium Risk", int((claims_df["risk_level"] == "MEDIUM").sum()))
        with c4:
            st.metric("Low Risk", int((claims_df["risk_level"] == "LOW").sum()))

        st.divider()
        search_col, filter_col = st.columns([2, 1])
        with search_col:
            search = st.text_input(
                "Search Previous Claims",
                placeholder="Claim, policy, customer or report reference",
                key="history_search",
            )
        with filter_col:
            risk_filter = st.selectbox(
                "Risk Filter", ["All", "HIGH", "MEDIUM", "LOW"], key="history_risk_filter"
            )

        filtered = claims_df.copy()
        if search:
            term = search.lower()
            filtered = filtered[
                filtered.astype(str)
                .apply(lambda row: row.str.lower().str.contains(term, na=False).any(), axis=1)
            ]
        if risk_filter != "All":
            filtered = filtered[filtered["risk_level"] == risk_filter]

        display_df = filtered[
            ["report_id", "claim_reference", "assessment_date", "fraud_score", "risk_level"]
        ].copy()
        display_df = display_df.rename(
            columns={
                "report_id": "Report ID",
                "claim_reference": "Claim Reference",
                "assessment_date": "Assessment Date",
                "fraud_score": "Fraud Risk %",
                "risk_level": "Risk Level",
            }
        )
        display_df["Fraud Risk %"] = display_df["Fraud Risk %"].map(lambda x: f"{safe_float(x):.2f}%")
        st.dataframe(display_df, use_container_width=True, hide_index=True)

        if not filtered.empty:
            st.divider()
            st.subheader("Open Saved Assessment")
            labels = []
            report_lookup = {}
            for _, row in filtered.iterrows():
                score_value = safe_float(row["fraud_score"])
                label = (
                    f"{row['claim_reference'] or 'No Claim Ref'} · {row['risk_level']} · "
                    f"{score_value:.2f}% · {row['assessment_date']}"
                )
                labels.append(label)
                report_lookup[label] = row["report_id"]

            placeholder = "— Select a saved claim to view its AI assessment —"
            selected = st.selectbox(
                "Saved claim",
                [placeholder] + labels,
                index=0,
                key="saved_claim_selector",
            )

            if selected != placeholder:
                saved = get_claim_by_report(
                    st.session_state.username, report_lookup[selected]
                )
                if saved is not None:
                    saved_claim_data = json_loads_safe(saved.get("claim_data"), {})
                    saved_analysis = json_loads_safe(saved.get("analysis_json"), {})
                    recommendation = saved.get("recommendation_text") or (
                        "Refer to the recommended action and complete the appropriate claim review."
                    )

                    # Old records may not have advanced analysis_json. Recompute if possible.
                    if not saved_analysis and saved_claim_data:
                        try:
                            old_df = pd.DataFrame([saved_claim_data])
                            old_df = old_df[categorical_columns + numerical_columns]
                            saved_analysis = build_ai_analysis(
                                old_df,
                                safe_float(saved["fraud_score"]),
                                saved["risk_level"],
                            )
                        except Exception:
                            old_factors = json_loads_safe(saved.get("risk_factors"), [])
                            saved_analysis = {
                                "summary": "This is a legacy saved assessment. Advanced SHAP detail was not stored with the original record.",
                                "risk_drivers": [
                                    {
                                        "field": "Legacy",
                                        "label": "Saved factor",
                                        "value": str(f),
                                        "contribution": 0,
                                        "share": 0,
                                        "impact": "Legacy record",
                                        "sensitive": False,
                                    }
                                    for f in old_factors[:5]
                                ],
                                "protective_factors": [],
                                "explanation_coverage": 0,
                                "sensitive_share": 0,
                                "investigation_plan": [
                                    "Review the original claim evidence and supporting documentation."
                                ],
                            }

                    st.divider()
                    display_assessment(
                        score=safe_float(saved["fraud_score"]),
                        risk_level=saved["risk_level"],
                        action_title=saved["recommended_action"],
                        recommendation=recommendation,
                        analysis=saved_analysis,
                        report_id=saved["report_id"],
                        claim_reference=saved["claim_reference"],
                        policy_reference=saved["policy_reference"],
                        customer_reference=saved["customer_reference"],
                        assessment_date=saved["assessment_date"],
                        claim_data=saved_claim_data,
                        source="history",
                    )

# ============================================================
# ABOUT THE AI
# ============================================================

st.divider()
with st.expander("ℹ️ About the InsureGuard AI methodology"):
    st.markdown(
        """
        **What is actually AI/ML here?**  
        InsureGuard uses a trained **XGBoost gradient-boosted decision-tree classifier** to estimate the probability
        that a claim resembles historically fraudulent claims. For each individual assessment, **SHAP (SHapley Additive
        exPlanations)** is used to explain how each original claim field moved the model prediction upward or downward.

        **What makes the explanation stronger than a list of one-word factors?**  
        One-hot encoded model features are aggregated back to their original business fields. InsureGuard then ranks
        the strongest risk drivers and risk-reducing factors, calculates each field's share of the local absolute SHAP
        contribution, generates an evidence-focused investigation checklist, and exposes sensitive-feature influence as
        a fairness/governance signal.

        **Important:** the score is a decision-support signal, not a fraud verdict. Final action must remain with an
        authorized human reviewer using evidence, policy rules and applicable legal/ethical requirements.
        """
    )

st.markdown(
    '<div class="small-note" style="text-align:center; margin-top:16px;">InsureGuard AI · Explainable Machine Learning for Insurance Fraud-Risk Assessment</div>',
    unsafe_allow_html=True,
)
