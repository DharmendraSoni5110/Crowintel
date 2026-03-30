import streamlit as st
import requests

st.set_page_config(page_title="Auto Pentest Tool", page_icon="🔥", layout="centered")

BACKEND_URL = "http://127.0.0.1:8000"

st.title("🔥 Automated Pentesting Tool")
st.markdown("Run scans and generate a PDF report automatically.")

st.markdown("### Target Configuration")

target = st.text_input(
    "Target URL",
    placeholder="https://example.com",
    help="Full URL including scheme (http:// or https://)",
)

scan_type = st.selectbox(
    "Scan Type",
    ["web", "api"],
    help="'web' runs ZAP + Nuclei + Nikto. 'api' also tests JWT and auth endpoints.",
)

col1, col2 = st.columns([1, 3])

with col1:
    start = st.button("🚀 Start Scan", use_container_width=True)

if start:
    if not target.strip():
        st.error("⚠️  Please enter a valid target URL.")
    elif not (target.startswith("http://") or target.startswith("https://")):
        st.error("⚠️  Target must start with http:// or https://")
    else:
        with st.spinner("Running scans... this may take several minutes ⏳"):
            try:
                response = requests.post(
                    f"{BACKEND_URL}/scan",
                    json={"target": target.strip(), "scan_type": scan_type},
                    timeout=600,  # 10 min max
                )
            except requests.exceptions.ConnectionError:
                st.error(
                    "❌ Could not connect to the backend. "
                    "Make sure `main.py` is running on port 8000."
                )
                st.stop()
            except requests.exceptions.Timeout:
                st.error("❌ Scan timed out after 10 minutes.")
                st.stop()

        if response.status_code == 200:
            result = response.json()
            st.success(f"✅ Scan Completed — {result.get('total_findings', 0)} findings")
            st.json(result)

            # Download the PDF report
            try:
                pdf_resp = requests.get(f"{BACKEND_URL}/download", timeout=30)
                if pdf_resp.status_code == 200:
                    st.download_button(
                        label="📄 Download PDF Report",
                        data=pdf_resp.content,
                        file_name="pentest_report.pdf",
                        mime="application/pdf",
                    )
                else:
                    st.warning("⚠️  Report generated but PDF download failed.")
            except requests.exceptions.RequestException as e:
                st.warning(f"⚠️  Could not fetch PDF: {e}")

        elif response.status_code == 400:
            st.error(f"❌ Bad request: {response.json().get('error', 'Unknown error')}")
        elif response.status_code == 500:
            st.error(f"❌ Server error: {response.json().get('error', 'Unknown error')}")
        else:
            st.error(f"❌ Unexpected response: HTTP {response.status_code}")

st.markdown("---")
st.caption("Powered by Crowintel")
