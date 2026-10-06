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
