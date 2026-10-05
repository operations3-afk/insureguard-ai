
import streamlit as st
import pandas as pd
import joblib
import shap
import sqlite3
import hashlib
import os
import json
import uuid
import struct

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
    PageBreak
)

# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="InsureGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ============================================================
# DESIGN
# ============================================================

st.markdown("""
<style>

.block-container {
    max-width: 1250px;
    padding-top: 1.5rem;
    padding-bottom: 3rem;
}

.main-title {
    font-size: 42px;
    font-weight: 750;
    color: #172033;
    margin-bottom: 7px;
}

.main-subtitle {
    font-size: 21px;
    font-weight: 600;
    color: #334155;
    margin-bottom: 8px;
}

.main-description {
    font-size: 15px;
    color: #64748b;
    margin-bottom: 22px;
}

.info-card {
    background: linear-gradient(145deg,#ffffff,#f7f9fc);
    border: 1px solid #e2e8f0;
    border-radius: 14px;
    padding: 18px 20px;
    min-height: 92px;
    box-shadow: 0 2px 10px rgba(15,23,42,.04);
}

.info-label {
    font-size: 11px;
    color: #64748b;
    font-weight: 700;
    letter-spacing: .7px;
    text-transform: uppercase;
}

.info-value {
    font-size: 20px;
    color: #172033;
    font-weight: 700;
    margin-top: 8px;
}

.result-card {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 14px;
    padding: 20px;
    min-height: 120px;
    box-shadow: 0 2px 10px rgba(15,23,42,.04);
}

.result-label {
    font-size: 11px;
    color: #64748b;
    font-weight: 700;
    letter-spacing: .6px;
    text-transform: uppercase;
}

.result-value {
    font-size: 29px;
    font-weight: 750;
    color: #172033;
    margin-top: 10px;
}

.risk-factor {
    background: #f8fafc;
    border: 1px solid #e5eaf1;
    border-left: 4px solid #315efb;
    padding: 12px 15px;
    margin-bottom: 9px;
    border-radius: 7px;
    color: #283548;
}

.small-note {
    font-size: 12px;
    color: #64748b;
}

div.stButton > button {
    border-radius: 8px;
    font-weight: 600;
}

div.stDownloadButton > button {
    min-height: 46px;
    border-radius: 9px;
    font-weight: 700;
}

</style>
""", unsafe_allow_html=True)

DB_PATH = "insureguard.db"

# ============================================================
# SAFE NUMBER HANDLING
# ============================================================

def safe_float(value):

    if value is None:
        return 0.0

    if isinstance(value, bytes):

        try:

            if len(value) == 8:
                return struct.unpack("d", value)[0]

            return float(
                value.decode()
            )

        except:
            return 0.0

    try:
        return float(value)

    except:
        return 0.0

# ============================================================
# DATABASE HELPERS
# ============================================================

def table_columns(cursor, table):

    cursor.execute(
        f"PRAGMA table_info({table})"
    )

    return [
        row[1]
        for row in cursor.fetchall()
    ]


def ensure_column(
    cursor,
    table,
    column,
    column_type
):

    if column not in table_columns(
        cursor,
        table
    ):

        cursor.execute(
            f"""
            ALTER TABLE {table}
            ADD COLUMN {column} {column_type}
            """
        )

# ============================================================
# PASSWORD SECURITY
# ============================================================

def create_password_hash(
    password,
    salt=None
):

    if salt is None:
        salt = os.urandom(16)

    password_hash = (
        hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            200000
        )
    )

    return (
        salt.hex(),
        password_hash.hex()
    )


def verify_password(
    password,
    salt_hex,
    hash_hex
):

    try:

        salt = bytes.fromhex(
            salt_hex
        )

        _, generated_hash = (
            create_password_hash(
                password,
                salt
            )
        )

        return (
            generated_hash
            == hash_hex
        )

    except:
        return False

# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_database():

    conn = sqlite3.connect(
        DB_PATH
    )

    cursor = conn.cursor()

    # USERS
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT,
        password_hash TEXT,
        password_salt TEXT,
        created_at TEXT
    )
    """)

    ensure_column(
        cursor,
        "users",
        "email",
        "TEXT"
    )

    ensure_column(
        cursor,
        "users",
        "password_hash",
        "TEXT"
    )

    ensure_column(
        cursor,
        "users",
        "password_salt",
        "TEXT"
    )

    ensure_column(
        cursor,
        "users",
        "created_at",
        "TEXT"
    )

    # CLAIMS
    cursor.execute("""
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
        claim_data TEXT
    )
    """)

    ensure_column(
        cursor,
        "claims",
        "username",
        "TEXT"
    )

    ensure_column(
        cursor,
        "claims",
        "risk_factors",
        "TEXT"
    )

    ensure_column(
        cursor,
        "claims",
        "recommendation_text",
        "TEXT"
    )

    ensure_column(
        cursor,
        "claims",
        "claim_data",
        "TEXT"
    )

    conn.commit()
    conn.close()


init_database()

# ============================================================
# USER FUNCTIONS
# ============================================================

def username_exists(
    username
):

    conn = sqlite3.connect(
        DB_PATH
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id
        FROM users
        WHERE LOWER(username)
        = LOWER(?)
        """,
        (username,)
    )

    exists = (
        cursor.fetchone()
        is not None
    )

    conn.close()

    return exists


def email_exists(
    email
):

    conn = sqlite3.connect(
        DB_PATH
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id
        FROM users
        WHERE LOWER(email)
        = LOWER(?)
        """,
        (email,)
    )

    exists = (
        cursor.fetchone()
        is not None
    )

    conn.close()

    return exists


def create_user(
    username,
    email,
    password
):

    salt, password_hash = (
        create_password_hash(
            password
        )
    )

    created_at = (
        datetime.now()
        .strftime(
            "%d %B %Y, %I:%M %p"
        )
    )

    conn = sqlite3.connect(
        DB_PATH
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO users (
            username,
            email,
            password_hash,
            password_salt,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            username,
            email,
            password_hash,
            salt,
            created_at
        )
    )

    conn.commit()
    conn.close()


def authenticate_user(
    username,
    password
):

    conn = sqlite3.connect(
        DB_PATH
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            username,
            email,
            password_hash,
            password_salt
        FROM users
        WHERE LOWER(username)
        = LOWER(?)
        """,
        (username,)
    )

    result = (
        cursor.fetchone()
    )

    conn.close()

    if result is None:
        return None

    username_db = result[0]
    email = result[1]
    password_hash = result[2]
    password_salt = result[3]

    if (
        not password_hash
        or not password_salt
    ):

        return None

    if verify_password(
        password,
        password_salt,
        password_hash
    ):

        return {
            "username": username_db,
            "email": email
        }

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
    claim_data
):

    conn = sqlite3.connect(
        DB_PATH
    )

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO claims (
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
            claim_data
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            json.dumps(
                risk_factors
            ),
            json.dumps(
                claim_data
            )
        )
    )

    conn.commit()
    conn.close()


def load_user_claims(
    username
):

    conn = sqlite3.connect(
        DB_PATH
    )

    df = pd.read_sql_query(
        """
        SELECT *
        FROM claims
        WHERE username = ?
        ORDER BY id DESC
        """,
        conn,
        params=(username,)
    )

    conn.close()

    if not df.empty:

        df["fraud_score"] = (
            df["fraud_score"]
            .apply(
                safe_float
            )
        )

    return df


def get_claim_by_report(
    username,
    report_id
):

    conn = sqlite3.connect(
        DB_PATH
    )

    df = pd.read_sql_query(
        """
        SELECT *
        FROM claims
        WHERE username = ?
        AND report_id = ?
        LIMIT 1
        """,
        conn,
        params=(
            username,
            report_id
        )
    )

    conn.close()

    if df.empty:
        return None

    row = (
        df.iloc[0]
        .copy()
    )

    row["fraud_score"] = (
        safe_float(
            row[
                "fraud_score"
            ]
        )
    )

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
        <div class="main-title">
            🛡️ InsureGuard AI
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        """
        <div class="main-subtitle">
            AI-Powered Insurance Fraud Risk Assessment
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        """
        <div class="main-description">
            Analyze insurance claims using machine learning
            and explainable AI to identify potentially suspicious
            claims and support insurance claim review.
        </div>
        """,
        unsafe_allow_html=True
    )

# ============================================================
# LOGIN / SIGN UP
# ============================================================

if not st.session_state.logged_in:

    show_brand_header()

    st.divider()

    login_tab, signup_tab = (
        st.tabs([
            "🔐 Login",
            "✨ Create Account"
        ])
    )

    # LOGIN
    with login_tab:

        _, login_col, _ = (
            st.columns(
                [1, 1.2, 1]
            )
        )

        with login_col:

            st.subheader(
                "Welcome Back"
            )

            st.write(
                "Sign in to access your claim assessments."
            )

            login_username = (
                st.text_input(
                    "Username",
                    key="login_username"
                )
            )

            login_password = (
                st.text_input(
                    "Password",
                    type="password",
                    key="login_password"
                )
            )

            if st.button(
                "Login",
                use_container_width=True,
                key="login_button"
            ):

                user = (
                    authenticate_user(
                        login_username.strip(),
                        login_password
                    )
                )

                if user:

                    st.session_state.logged_in = True

                    st.session_state.username = (
                        user["username"]
                    )

                    st.session_state.email = (
                        user["email"]
                    )

                    st.rerun()

                else:

                    st.error(
                        "Incorrect username or password."
                    )

    # SIGN UP
    with signup_tab:

        _, signup_col, _ = (
            st.columns(
                [1, 1.2, 1]
            )
        )

        with signup_col:

            st.subheader(
                "Create Your Account"
            )

            new_username = (
                st.text_input(
                    "Username",
                    key="signup_username"
                )
            )

            new_email = (
                st.text_input(
                    "Email Address",
                    key="signup_email"
                )
            )

            new_password = (
                st.text_input(
                    "Password",
                    type="password",
                    key="signup_password"
                )
            )

            confirm_password = (
                st.text_input(
                    "Confirm Password",
                    type="password",
                    key="signup_confirm"
                )
            )

            st.caption(
                "Password must contain at least 8 characters."
            )

            if st.button(
                "Create Account",
                use_container_width=True,
                key="create_account_button"
            ):

                username = (
                    new_username
                    .strip()
                )

                email = (
                    new_email
                    .strip()
                )

                if len(username) < 3:

                    st.error(
                        "Username must contain at least 3 characters."
                    )

                elif "@" not in email:

                    st.error(
                        "Please enter a valid email address."
                    )

                elif len(
                    new_password
                ) < 8:

                    st.error(
                        "Password must contain at least 8 characters."
                    )

                elif (
                    new_password
                    != confirm_password
                ):

                    st.error(
                        "Passwords do not match."
                    )

                elif username_exists(
                    username
                ):

                    st.error(
                        "That username already exists."
                    )

                elif email_exists(
                    email
                ):

                    st.error(
                        "That email address is already registered."
                    )

                else:

                    create_user(
                        username,
                        email,
                        new_password
                    )

                    st.success(
                        "Account created successfully. "
                        "You can now log in."
                    )

    st.stop()

# ============================================================
# LOAD AI MODEL
# ============================================================

model = joblib.load(
    "insureguard_model.pkl"
)

model_info = joblib.load(
    "insureguard_model_info.pkl"
)

categorical_columns = (
    model_info[
        "categorical_columns"
    ]
)

numerical_columns = (
    model_info[
        "numerical_columns"
    ]
)

category_options = {
    key: list(values)
    for key, values
    in model_info[
        "category_options"
    ].items()
}

medium_threshold = (
    model_info.get(
        "medium_risk_threshold",
        0.40
    )
)

high_threshold = (
    model_info.get(
        "high_risk_threshold",
        0.65
    )
)

for column in [
    "DayOfWeekClaimed",
    "MonthClaimed"
]:

    if column in category_options:

        category_options[column] = [
            value
            for value
            in category_options[column]
            if str(value) != "0"
        ]

# ============================================================
# SHAP
# ============================================================

feature_names = (
    model
    .named_steps[
        "preprocessor"
    ]
    .get_feature_names_out()
)

explainer = shap.TreeExplainer(
    model.named_steps[
        "classifier"
    ]
)

# ============================================================
# LABELS
# ============================================================

field_labels = {

    "Month":
        "Accident Month",

    "WeekOfMonth":
        "Accident Week of Month",

    "DayOfWeek":
        "Accident Day",

    "Make":
        "Vehicle Make",

    "AccidentArea":
        "Accident Area",

    "DayOfWeekClaimed":
        "Claim Report Day",

    "MonthClaimed":
        "Claim Month",

    "WeekOfMonthClaimed":
        "Claim Week of Month",

    "Sex":
        "Policy Holder Gender",

    "MaritalStatus":
        "Marital Status",

    "Age":
        "Policy Holder Age",

    "Fault":
        "Fault",

    "PolicyType":
        "Policy Type",

    "VehicleCategory":
        "Vehicle Category",

    "VehiclePrice":
        "Vehicle Price Range",

    "RepNumber":
        "Representative Number",

    "Deductible":
        "Deductible Amount",

    "DriverRating":
        "Driver Rating",

    "Days_Policy_Accident":
        "Policy Age at Accident",

    "Days_Policy_Claim":
        "Policy Age at Claim",

    "PastNumberOfClaims":
        "Previous Claims",

    "AgeOfVehicle":
        "Vehicle Age",

    "AgeOfPolicyHolder":
        "Policy Holder Age Group",

    "PoliceReportFiled":
        "Police Report Filed",

    "WitnessPresent":
        "Witness Present",

    "AgentType":
        "Agent Type",

    "NumberOfSuppliments":
        "Number of Supplements",

    "AddressChange_Claim":
        "Time Since Address Change",

    "NumberOfCars":
        "Number of Vehicles",

    "Year":
        "Claim Year",

    "BasePolicy":
        "Base Policy"
}

policyholder_fields = [

    "Sex",
    "MaritalStatus",
    "Age",
    "AgeOfPolicyHolder",
    "AddressChange_Claim"
]

vehicle_fields = [

    "Make",
    "VehicleCategory",
    "VehiclePrice",
    "AgeOfVehicle",
    "NumberOfCars",
    "DriverRating"
]

accident_fields = [

    "Month",
    "WeekOfMonth",
    "DayOfWeek",
    "AccidentArea",
    "Fault",
    "PoliceReportFiled",
    "WitnessPresent"
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

    "Year"
]

# ============================================================
# FORM FIELD RENDERER
# ============================================================

def render_field(
    column,
    inputs
):

    label = (
        field_labels.get(
            column,
            column
        )
    )

    if column in categorical_columns:

        inputs[column] = (
            st.selectbox(
                label,
                category_options[
                    column
                ],
                key=column
            )
        )

        return

    if column == "Age":

        inputs[column] = (
            st.number_input(
                label,
                min_value=16,
                max_value=100,
                value=35,
                step=1,
                key=column
            )
        )

    elif column == "DriverRating":

        inputs[column] = (
            st.number_input(
                label,
                min_value=1,
                max_value=4,
                value=2,
                step=1,
                key=column
            )
        )

    elif column == "Deductible":

        inputs[column] = (
            st.number_input(
                label,
                min_value=0,
                value=400,
                step=100,
                key=column
            )
        )

    elif column in [
        "WeekOfMonth",
        "WeekOfMonthClaimed"
    ]:

        inputs[column] = (
            st.number_input(
                label,
                min_value=1,
                max_value=5,
                value=1,
                step=1,
                key=column
            )
        )

    elif column == "RepNumber":

        inputs[column] = (
            st.number_input(
                label,
                min_value=1,
                max_value=16,
                value=1,
                step=1,
                key=column
            )
        )

    elif column == "Year":

        inputs[column] = (
            st.number_input(
                label,
                min_value=1990,
                max_value=2035,
                value=1994,
                step=1,
                key=column
            )
        )

    else:

        inputs[column] = (
            st.number_input(
                label,
                value=1,
                step=1,
                key=column
            )
        )

# ============================================================
# SHAP FEATURE NAMES
# ============================================================

def clean_feature_name(
    feature
):

    feature = (
        feature
        .replace(
            "cat__",
            ""
        )
        .replace(
            "num__",
            ""
        )
    )

    replacements = {

        "AddressChange_Claim_":
            "Time Since Address Change: ",

        "BasePolicy_":
            "Base Policy: ",

        "Fault_":
            "Fault: ",

        "PolicyType_":
            "Policy Type: ",

        "VehiclePrice_":
            "Vehicle Price: ",

        "AccidentArea_":
            "Accident Area: ",

        "Month_":
            "Accident Month: ",

        "MonthClaimed_":
            "Claim Month: ",

        "AgeOfVehicle_":
            "Vehicle Age: ",

        "PastNumberOfClaims_":
            "Previous Claims: ",

        "PoliceReportFiled_":
            "Police Report Filed: ",

        "WitnessPresent_":
            "Witness Present: ",

        "AgentType_":
            "Agent Type: ",

        "Make_":
            "Vehicle Make: ",

        "VehicleCategory_":
            "Vehicle Category: ",

        "AgeOfPolicyHolder_":
            "Policy Holder Age Group: ",

        "DayOfWeek_":
            "Accident Day: ",

        "DayOfWeekClaimed_":
            "Claim Report Day: "
    }

    for old, new in (
        replacements.items()
    ):

        feature = (
            feature.replace(
                old,
                new
            )
        )

    return feature

# ============================================================
# PDF DESIGN
# ============================================================

PDF_NAVY = colors.HexColor(
    "#16213A"
)

PDF_BLUE = colors.HexColor(
    "#315EFB"
)

PDF_LIGHT = colors.HexColor(
    "#F7F9FC"
)

PDF_LINE = colors.HexColor(
    "#E1E7EF"
)

PDF_TEXT = colors.HexColor(
    "#263445"
)

PDF_MUTED = colors.HexColor(
    "#667085"
)

PDF_GREEN = colors.HexColor(
    "#1C9A65"
)

PDF_GREEN_BG = colors.HexColor(
    "#EAF8F1"
)

PDF_AMBER = colors.HexColor(
    "#D78A00"
)

PDF_AMBER_BG = colors.HexColor(
    "#FFF7E7"
)

PDF_RED = colors.HexColor(
    "#D14343"
)

PDF_RED_BG = colors.HexColor(
    "#FFF0F0"
)

# ============================================================
# PDF HEADER / FOOTER
# ============================================================

def pdf_header_footer(
    canvas,
    doc
):

    canvas.saveState()

    width, height = A4

    canvas.setFillColor(
        PDF_NAVY
    )

    canvas.rect(
        0,
        height - 18 * mm,
        width,
        18 * mm,
        fill=1,
        stroke=0
    )

    canvas.setFillColor(
        colors.white
    )

    canvas.setFont(
        "Helvetica-Bold",
        10
    )

    canvas.drawString(
        15 * mm,
        height - 11 * mm,
        "INSUREGUARD AI"
    )

    canvas.setStrokeColor(
        PDF_LINE
    )

    canvas.line(
        15 * mm,
        14 * mm,
        width - 15 * mm,
        14 * mm
    )

    canvas.setFillColor(
        PDF_MUTED
    )

    canvas.setFont(
        "Helvetica",
        7
    )

    canvas.drawString(
        15 * mm,
        9 * mm,
        "Confidential · AI Decision Support Assessment"
    )

    canvas.drawRightString(
        width - 15 * mm,
        9 * mm,
        f"Page {doc.page}"
    )

    canvas.restoreState()

# ============================================================
# PDF TABLE
# ============================================================

def make_pdf_table(
    rows
):

    table = Table(
        rows,
        colWidths=[
            55 * mm,
            115 * mm
        ]
    )

    table.setStyle(
        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                PDF_LIGHT
            ),

            (
                "FONTNAME",
                (0, 0),
                (0, -1),
                "Helvetica-Bold"
            ),

            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                8
            ),

            (
                "TEXTCOLOR",
                (0, 0),
                (-1, -1),
                PDF_TEXT
            ),

            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.5,
                PDF_LINE
            ),

            (
                "INNERGRID",
                (0, 0),
                (-1, -1),
                0.35,
                PDF_LINE
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7
            ),

            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                8
            )
        ])
    )

    return table

# ============================================================
# CREATE PDF
# ============================================================

def create_pdf_report(
    report_id,
    claim_reference,
    policy_reference,
    customer_reference,
    assessment_date,
    score,
    risk_level,
    action_title,
    factors,
    recommendation,
    claim_data
):

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=27 * mm,
        bottomMargin=20 * mm
    )

    styles = (
        getSampleStyleSheet()
    )

    title_style = (
        ParagraphStyle(
            "CustomTitle",
            parent=styles[
                "Title"
            ],
            fontSize=22,
            textColor=PDF_NAVY,
            spaceAfter=6
        )
    )

    section_style = (
        ParagraphStyle(
            "Section",
            parent=styles[
                "Heading2"
            ],
            fontSize=13,
            textColor=PDF_NAVY,
            spaceBefore=10,
            spaceAfter=8
        )
    )

    body_style = (
        ParagraphStyle(
            "Body",
            parent=styles[
                "BodyText"
            ],
            fontSize=9,
            leading=14,
            textColor=PDF_TEXT
        )
    )

    story = []

    story.append(
        Paragraph(
            "Insurance Fraud Risk Assessment",
            title_style
        )
    )

    story.append(
        Paragraph(
            "AI-powered claim screening with explainable AI",
            body_style
        )
    )

    story.append(
        Spacer(
            1,
            12
        )
    )

    # CASE INFO
    story.append(
        Paragraph(
            "Case Information",
            section_style
        )
    )

    story.append(
        make_pdf_table([

            [
                "Report ID",
                report_id
            ],

            [
                "Claim Reference",
                claim_reference
                or "Not provided"
            ],

            [
                "Policy Reference",
                policy_reference
                or "Not provided"
            ],

            [
                "Customer Reference",
                customer_reference
                or "Not provided"
            ],

            [
                "Assessment Date",
                assessment_date
            ],

            [
                "Account",
                st.session_state.username
            ],

            [
                "Model",
                "XGBoost + SHAP"
            ]
        ])
    )

    story.append(
        Spacer(
            1,
            14
        )
    )

    # RISK COLOR
    if risk_level == "HIGH":

        risk_color = PDF_RED
        risk_bg = PDF_RED_BG

    elif risk_level == "MEDIUM":

        risk_color = PDF_AMBER
        risk_bg = PDF_AMBER_BG

    else:

        risk_color = PDF_GREEN
        risk_bg = PDF_GREEN_BG

    # RISK TABLE
    story.append(
        Paragraph(
            "Risk Assessment Summary",
            section_style
        )
    )

    risk_table = Table(
        [
            [
                "FRAUD RISK SCORE",
                "RISK LEVEL",
                "RECOMMENDED ACTION"
            ],
            [
                f"{score:.2f}%",
                risk_level,
                action_title
            ]
        ],
        colWidths=[
            50 * mm,
            45 * mm,
            75 * mm
        ]
    )

    risk_table.setStyle(
        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor(
                    "#EEF4FF"
                )
            ),

            (
                "BACKGROUND",
                (1, 1),
                (1, 1),
                risk_bg
            ),

            (
                "TEXTCOLOR",
                (1, 1),
                (1, 1),
                risk_color
            ),

            (
                "FONTNAME",
                (0, 0),
                (-1, -1),
                "Helvetica-Bold"
            ),

            (
                "ALIGN",
                (0, 0),
                (-1, -1),
                "CENTER"
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),

            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.6,
                PDF_LINE
            ),

            (
                "INNERGRID",
                (0, 0),
                (-1, -1),
                0.35,
                PDF_LINE
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                9
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                9
            )
        ])
    )

    story.append(
        risk_table
    )

    story.append(
        Spacer(
            1,
            14
        )
    )

    # XAI
    story.append(
        Paragraph(
            "Explainable AI Analysis",
            section_style
        )
    )

    factor_rows = [

        [
            str(i),
            factor
        ]

        for i, factor
        in enumerate(
            factors,
            start=1
        )
    ]

    factor_table = Table(
        factor_rows,
        colWidths=[
            10 * mm,
            160 * mm
        ]
    )

    factor_table.setStyle(
        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                PDF_BLUE
            ),

            (
                "TEXTCOLOR",
                (0, 0),
                (0, -1),
                colors.white
            ),

            (
                "BACKGROUND",
                (1, 0),
                (1, -1),
                PDF_LIGHT
            ),

            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.4,
                PDF_LINE
            ),

            (
                "INNERGRID",
                (0, 0),
                (-1, -1),
                0.3,
                PDF_LINE
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    story.append(
        factor_table
    )

    story.append(
        Spacer(
            1,
            14
        )
    )

    # RECOMMENDATION
    story.append(
        Paragraph(
            "Investigation Recommendation",
            section_style
        )
    )

    recommendation_table = Table(
        [[
            Paragraph(
                recommendation,
                body_style
            )
        ]],
        colWidths=[
            170 * mm
        ]
    )

    recommendation_table.setStyle(
        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                risk_bg
            ),

            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.8,
                risk_color
            ),

            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                12
            ),

            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                12
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                11
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                11
            )
        ])
    )

    story.append(
        recommendation_table
    )

    # PAGE 2
    story.append(
        PageBreak()
    )

    story.append(
        Paragraph(
            "Assessment Methodology & Governance",
            title_style
        )
    )

    story.append(
        Spacer(
            1,
            8
        )
    )

    story.append(
        make_pdf_table([

            [
                "Prediction Model",
                "XGBoost Classifier"
            ],

            [
                "Explainability",
                "SHAP"
            ],

            [
                "Risk Levels",
                "Low / Medium / High"
            ],

            [
                "Medium Threshold",
                f"{medium_threshold * 100:.0f}%"
            ],

            [
                "High Threshold",
                f"{high_threshold * 100:.0f}%"
            ]
        ])
    )

    story.append(
        Spacer(
            1,
            15
        )
    )

    story.append(
        Paragraph(
            "Human Review Requirement",
            section_style
        )
    )

    story.append(
        Paragraph(
            "InsureGuard is a decision-support system. "
            "It does not independently determine whether fraud occurred. "
            "Supporting evidence, documentation, investigation results "
            "and authorized human judgment remain required.",
            body_style
        )
    )

    story.append(
        Spacer(
            1,
            15
        )
    )

    story.append(
        Paragraph(
            "Important Limitations",
            section_style
        )
    )

    limitations = [

        "The model is based on historical insurance claim data.",

        "A high risk score does not prove fraudulent intent.",

        "False positives and false negatives are possible.",

        "Predictions should be combined with human investigation.",

        "The model should be periodically evaluated and retrained."
    ]

    for limitation in limitations:

        story.append(
            Paragraph(
                f"• {limitation}",
                body_style
            )
        )

        story.append(
            Spacer(
                1,
                4
            )
        )

    doc.build(
        story,
        onFirstPage=(
            pdf_header_footer
        ),
        onLaterPages=(
            pdf_header_footer
        )
    )

    buffer.seek(0)

    return buffer

# ============================================================
# DISPLAY ASSESSMENT
# ============================================================

def display_assessment(
    score,
    risk_level,
    action_title,
    factors,
    recommendation,
    report_id,
    claim_reference,
    policy_reference,
    customer_reference,
    assessment_date,
    claim_data
):

    if risk_level == "HIGH":
        icon = "🔴"

    elif risk_level == "MEDIUM":
        icon = "🟠"

    else:
        icon = "🟢"

    st.header(
        "AI Risk Assessment"
    )

    c1, c2, c3 = (
        st.columns(3)
    )

    with c1:

        st.markdown(
            f"""
            <div class="result-card">
                <div class="result-label">
                    Fraud Risk Score
                </div>
                <div class="result-value">
                    {score:.2f}%
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with c2:

        st.markdown(
            f"""
            <div class="result-card">
                <div class="result-label">
                    Risk Level
                </div>
                <div class="result-value">
                    {icon} {risk_level}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with c3:

        st.markdown(
            f"""
            <div class="result-card">
                <div class="result-label">
                    Recommended Action
                </div>
                <div class="result-value"
                     style="font-size:18px;">
                    {action_title}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.write(
        "#### Risk Indicator"
    )

    st.progress(
        max(
            0,
            min(
                int(score),
                100
            )
        )
    )

    st.markdown(
        """
        <div class="small-note">
        The risk score is a machine-learning risk indicator based on
        historical claim patterns. It is not proof that fraud occurred.
        </div>
        """,
        unsafe_allow_html=True
    )

    st.subheader(
        "🧠 Explainable AI Analysis"
    )

    st.write(
        "The following characteristics contributed most strongly "
        "toward increasing the predicted fraud-risk score:"
    )

    for factor in factors:

        st.markdown(
            f"""
            <div class="risk-factor">
                {factor}
            </div>
            """,
            unsafe_allow_html=True
        )

    st.subheader(
        "Recommended Action"
    )

    if risk_level == "HIGH":

        st.error(
            recommendation
        )

    elif risk_level == "MEDIUM":

        st.warning(
            recommendation
        )

    else:

        st.success(
            recommendation
        )

    st.subheader(
        "Assessment Details"
    )

    d1, d2 = (
        st.columns(2)
    )

    with d1:

        st.write(
            "**Report ID:**",
            report_id
        )

        st.write(
            "**Claim Reference:**",
            claim_reference
            or "Not provided"
        )

        st.write(
            "**Policy Reference:**",
            policy_reference
            or "Not provided"
        )

    with d2:

        st.write(
            "**Customer Reference:**",
            customer_reference
            or "Not provided"
        )

        st.write(
            "**Assessment Date:**",
            assessment_date
        )

    pdf = (
        create_pdf_report(

            report_id=(
                report_id
            ),

            claim_reference=(
                claim_reference
            ),

            policy_reference=(
                policy_reference
            ),

            customer_reference=(
                customer_reference
            ),

            assessment_date=(
                assessment_date
            ),

            score=score,

            risk_level=(
                risk_level
            ),

            action_title=(
                action_title
            ),

            factors=(
                factors
            ),

            recommendation=(
                recommendation
            ),

            claim_data=(
                claim_data
            )
        )
    )

    st.download_button(

        "⬇️ Download PDF Assessment",

        data=pdf,

        file_name=(
            f"InsureGuard_"
            f"{claim_reference if claim_reference else report_id}"
            "_Assessment.pdf"
        ),

        mime=(
            "application/pdf"
        ),

        use_container_width=True
    )

# ============================================================
# LOGGED-IN TOP BAR
# ============================================================

space, user_col, logout_col = (
    st.columns(
        [6.2, 1.5, 0.8]
    )
)

with user_col:

    st.markdown(
        f"""
        <div style="
            text-align:right;
            padding-top:8px;
            color:#334155;
            font-size:14px;">
            👤 <b>{st.session_state.username}</b>
        </div>
        """,
        unsafe_allow_html=True
    )

with logout_col:

    if st.button(
        "Log out",
        key="top_logout"
    ):

        st.session_state.logged_in = False

        st.session_state.username = None

        st.session_state.email = None

        st.rerun()

show_brand_header()

# ============================================================
# APP TABS
# ============================================================

tab_new, tab_history = (
    st.tabs([
        "🔍 New Assessment",
        "📚 Previous Claims"
    ])
)

# ============================================================
# NEW ASSESSMENT
# ============================================================

with tab_new:

    info1, info2, info3 = (
        st.columns(3)
    )

    with info1:

        st.markdown("""
        <div class="info-card">
            <div class="info-label">
                Prediction Model
            </div>
            <div class="info-value">
                XGBoost
            </div>
        </div>
        """, unsafe_allow_html=True)

    with info2:

        st.markdown("""
        <div class="info-card">
            <div class="info-label">
                Risk Classification
            </div>
            <div class="info-value">
                Low · Medium · High
            </div>
        </div>
        """, unsafe_allow_html=True)

    with info3:

        st.markdown("""
        <div class="info-card">
            <div class="info-label">
                Explainable AI
            </div>
            <div class="info-value">
                SHAP Analysis
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.divider()

    st.header(
        "New Claim Assessment"
    )

    st.info(
        "InsureGuard is a decision-support system. "
        "It does not independently determine whether fraud occurred."
    )

    # --------------------------------------------------------
    # REFERENCES
    # --------------------------------------------------------

    st.subheader(
        "📋 Assessment Information"
    )

    r1, r2, r3 = (
        st.columns(3)
    )

    with r1:

        claim_reference = (
            st.text_input(
                "Claim Reference",
                placeholder="CLM-2026-001"
            )
        )

    with r2:

        policy_reference = (
            st.text_input(
                "Policy Reference",
                placeholder="POL-001245"
            )
        )

    with r3:

        customer_reference = (
            st.text_input(
                "Customer Reference",
                placeholder="CUST-1001"
            )
        )

    st.caption(
        "These references are stored with the assessment "
        "but are not used by the prediction model."
    )

    st.divider()

    # --------------------------------------------------------
    # CLAIM FORM
    # --------------------------------------------------------

    inputs = {}

    with st.form(
        "claim_form"
    ):

        st.subheader(
            "👤 Policy Holder Details"
        )

        left, right = (
            st.columns(2)
        )

        for i, field in enumerate(
            policyholder_fields
        ):

            with (
                left
                if i % 2 == 0
                else right
            ):

                render_field(
                    field,
                    inputs
                )

        st.divider()

        st.subheader(
            "🚗 Vehicle Details"
        )

        left, right = (
            st.columns(2)
        )

        for i, field in enumerate(
            vehicle_fields
        ):

            with (
                left
                if i % 2 == 0
                else right
            ):

                render_field(
                    field,
                    inputs
                )

        st.divider()

        st.subheader(
            "⚠️ Accident Details"
        )

        left, right = (
            st.columns(2)
        )

        for i, field in enumerate(
            accident_fields
        ):

            with (
                left
                if i % 2 == 0
                else right
            ):

                render_field(
                    field,
                    inputs
                )

        st.divider()

        st.subheader(
            "📄 Claim & Policy Details"
        )

        left, right = (
            st.columns(2)
        )

        for i, field in enumerate(
            claim_policy_fields
        ):

            with (
                left
                if i % 2 == 0
                else right
            ):

                render_field(
                    field,
                    inputs
                )

        st.divider()

        analyze = (
            st.form_submit_button(
                "🔍 Analyze Claim",
                use_container_width=True
            )
        )

    # --------------------------------------------------------
    # ANALYZE
    # --------------------------------------------------------

    if analyze:

        claim_df = (
            pd.DataFrame(
                [inputs]
            )
        )

        claim_df = (
            claim_df[
                categorical_columns
                + numerical_columns
            ]
        )

        probability = (
            model
            .predict_proba(
                claim_df
            )[0][1]
        )

        score = float(
            probability
            * 100
        )

        # RISK
        if (
            probability
            >= high_threshold
        ):

            risk_level = "HIGH"

            action_title = (
                "Manual Investigation Recommended"
            )

            recommendation = (
                "This claim displays characteristics associated "
                "with higher fraud risk. Manual verification and "
                "further investigation are recommended before "
                "approval or settlement."
            )

        elif (
            probability
            >= medium_threshold
        ):

            risk_level = "MEDIUM"

            action_title = (
                "Additional Verification Recommended"
            )

            recommendation = (
                "The model identified potentially suspicious "
                "claim characteristics. Additional documentation "
                "checks and verification are recommended."
            )

        else:

            risk_level = "LOW"

            action_title = (
                "Standard Processing May Continue"
            )

            recommendation = (
                "The claim currently shows a relatively low "
                "fraud-risk score. Standard claim processing "
                "may continue subject to normal review."
            )

        # SHAP
        transformed = (
            model
            .named_steps[
                "preprocessor"
            ]
            .transform(
                claim_df
            )
        )

        shap_values = (
            explainer
            .shap_values(
                transformed
            )
        )

        shap_array = (
            shap_values[0]
        )

        explanation_df = (
            pd.DataFrame({

                "Feature":
                    feature_names,

                "SHAP_Value":
                    shap_array
            })
        )

        fraud_factors = (

            explanation_df[
                explanation_df[
                    "SHAP_Value"
                ] > 0
            ]

            .sort_values(
                "SHAP_Value",
                ascending=False
            )

            .head(5)
        )

        factors = []

        for _, row in (
            fraud_factors
            .iterrows()
        ):

            feature = (
                row["Feature"]
            )

            readable = (
                clean_feature_name(
                    feature
                )
            )

            if feature.startswith(
                "num__"
            ):

                original = (
                    feature.replace(
                        "num__",
                        ""
                    )
                )

                if original in (
                    claim_df.columns
                ):

                    actual = (
                        claim_df
                        .iloc[0][
                            original
                        ]
                    )

                    readable = (
                        f"{field_labels.get(original, original)}: "
                        f"{actual}"
                    )

            factors.append(
                readable
            )

        if not factors:

            factors = [
                "No strong fraud-risk factors identified."
            ]

        # REPORT DETAILS
        assessment_date = (
            datetime.now()
            .strftime(
                "%d %B %Y, %I:%M %p"
            )
        )

        report_id = (
            "IGA-"
            + datetime.now()
            .strftime(
                "%Y%m%d"
            )
            + "-"
            + uuid.uuid4()
            .hex[:6]
            .upper()
        )

        claim_data = (
            claim_df
            .iloc[0]
            .to_dict()
        )

        # SAVE
        save_claim(

            report_id=(
                report_id
            ),

            username=(
                st.session_state.username
            ),

            claim_reference=(
                claim_reference
            ),

            policy_reference=(
                policy_reference
            ),

            customer_reference=(
                customer_reference
            ),

            assessment_date=(
                assessment_date
            ),

            fraud_score=(
                score
            ),

            risk_level=(
                risk_level
            ),

            recommended_action=(
                action_title
            ),

            recommendation_text=(
                recommendation
            ),

            risk_factors=(
                factors
            ),

            claim_data=(
                claim_data
            )
        )

        st.divider()

        # DISPLAY
        display_assessment(

            score=(
                score
            ),

            risk_level=(
                risk_level
            ),

            action_title=(
                action_title
            ),

            factors=(
                factors
            ),

            recommendation=(
                recommendation
            ),

            report_id=(
                report_id
            ),

            claim_reference=(
                claim_reference
            ),

            policy_reference=(
                policy_reference
            ),

            customer_reference=(
                customer_reference
            ),

            assessment_date=(
                assessment_date
            ),

            claim_data=(
                claim_data
            )
        )

# ============================================================
# PREVIOUS CLAIMS
# ============================================================

with tab_history:

    st.header(
        "Previous Claims"
    )

    claims_df = (
        load_user_claims(
            st.session_state.username
        )
    )

    if claims_df.empty:

        st.info(
            "You have not analyzed any claims yet."
        )

    else:

        c1, c2, c3, c4 = (
            st.columns(4)
        )

        with c1:

            st.metric(
                "Total Claims",
                len(
                    claims_df
                )
            )

        with c2:

            st.metric(
                "High Risk",
                len(
                    claims_df[
                        claims_df[
                            "risk_level"
                        ] == "HIGH"
                    ]
                )
            )

        with c3:

            st.metric(
                "Medium Risk",
                len(
                    claims_df[
                        claims_df[
                            "risk_level"
                        ] == "MEDIUM"
                    ]
                )
            )

        with c4:

            st.metric(
                "Low Risk",
                len(
                    claims_df[
                        claims_df[
                            "risk_level"
                        ] == "LOW"
                    ]
                )
            )

        st.divider()

        search = (
            st.text_input(
                "Search Previous Claims",
                placeholder=(
                    "Claim, policy, customer or report reference"
                )
            )
        )

        filtered = (
            claims_df.copy()
        )

        if search:

            term = (
                search.lower()
            )

            filtered = filtered[
                filtered
                .astype(str)
                .apply(
                    lambda row:
                    row
                    .str.lower()
                    .str.contains(
                        term,
                        na=False
                    )
                    .any(),
                    axis=1
                )
            ]

        display_df = (
            filtered[[
                "report_id",
                "claim_reference",
                "assessment_date",
                "fraud_score",
                "risk_level"
            ]]
            .copy()
        )

        display_df = (
            display_df.rename(
                columns={

                    "report_id":
                        "Report ID",

                    "claim_reference":
                        "Claim Reference",

                    "assessment_date":
                        "Assessment Date",

                    "fraud_score":
                        "Fraud Risk %",

                    "risk_level":
                        "Risk Level"
                }
            )
        )

        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True
        )

        # OPEN SAVED REPORT
        if not filtered.empty:

            st.divider()

            st.subheader(
                "Open Saved Assessment"
            )

            labels = []
            report_lookup = {}

            for _, row in (
                filtered.iterrows()
            ):

                score_value = (
                    safe_float(
                        row[
                            "fraud_score"
                        ]
                    )
                )

                label = (
                    f"{row['claim_reference'] or 'No Claim Ref'} "
                    f"· {row['risk_level']} "
                    f"· {score_value:.2f}% "
                    f"· {row['assessment_date']}"
                )

                labels.append(
                    label
                )

                report_lookup[
                    label
                ] = (
                    row[
                        "report_id"
                    ]
                )

            selected = (
                st.selectbox(
                    "Select an assessment",
                    labels
                )
            )

            if selected:

                saved = (
                    get_claim_by_report(
                        st.session_state.username,
                        report_lookup[
                            selected
                        ]
                    )
                )

                if saved is not None:

                    # FACTORS
                    try:

                        factors = (
                            json.loads(
                                saved[
                                    "risk_factors"
                                ]
                            )
                        )

                    except:

                        raw = (
                            saved[
                                "risk_factors"
                            ]
                        )

                        if isinstance(
                            raw,
                            str
                        ):

                            factors = [
                                x.strip()
                                for x in (
                                    raw.split(
                                        "|"
                                    )
                                )
                                if x.strip()
                            ]

                        else:

                            factors = []

                    if not factors:

                        factors = [
                            "No saved explainability factors available."
                        ]

                    # SAVED CLAIM DATA
                    try:

                        saved_claim_data = (
                            json.loads(
                                saved[
                                    "claim_data"
                                ]
                            )
                        )

                    except:

                        saved_claim_data = {}

                    recommendation = (
                        saved[
                            "recommendation_text"
                        ]
                    )

                    if not recommendation:

                        recommendation = (
                            "Refer to the recommended action "
                            "and complete the appropriate claim review."
                        )

                    st.divider()

                    display_assessment(

                        score=(
                            safe_float(
                                saved[
                                    "fraud_score"
                                ]
                            )
                        ),

                        risk_level=(
                            saved[
                                "risk_level"
                            ]
                        ),

                        action_title=(
                            saved[
                                "recommended_action"
                            ]
                        ),

                        factors=(
                            factors
                        ),

                        recommendation=(
                            recommendation
                        ),

                        report_id=(
                            saved[
                                "report_id"
                            ]
                        ),

                        claim_reference=(
                            saved[
                                "claim_reference"
                            ]
                        ),

                        policy_reference=(
                            saved[
                                "policy_reference"
                            ]
                        ),

                        customer_reference=(
                            saved[
                                "customer_reference"
                            ]
                        ),

                        assessment_date=(
                            saved[
                                "assessment_date"
                            ]
                        ),

                        claim_data=(
                            saved_claim_data
                        )
                    )

# ============================================================
# FOOTER
# ============================================================

st.divider()

st.markdown(
    """
    <div class="small-note"
         style="text-align:center;">
        InsureGuard AI · Machine Learning & Explainable AI
        for Insurance Fraud Risk Assessment
    </div>
    """,
    unsafe_allow_html=True
)
