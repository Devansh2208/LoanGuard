from flask import Flask, request, jsonify, redirect, session, url_for, render_template, send_from_directory, send_file
from flask_cors import CORS
from authlib.integrations.flask_client import OAuth
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from io import BytesIO
from datetime import datetime
import boto3
import re
import os
import logging
from functools import wraps
from botocore.exceptions import ClientError
import requests
import jwt
import secrets
from flask_session import Session  # Import the secrets module for secure token generation

# ------------------- Flask Setup -------------------
app = Flask(__name__, static_folder='../static', template_folder='../templates')
CORS(app, supports_credentials=True)
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = "./flask_session_dir"
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = 600  # 10 minutes
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # allows OAuth redirect
app.config["SESSION_COOKIE_SECURE"] = False     # True if HTTPS
Session(app)



# ------------------- AWS Setup -------------------
AWS_REGION = 'ap-south-1'
S3_BUCKET = 'loan-document-upload-bucket'

s3 = boto3.client('s3', region_name=AWS_REGION)
textract = boto3.client('textract', region_name=AWS_REGION)
rekognition = boto3.client('rekognition', region_name=AWS_REGION)
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
table_name = "LoanGuardDocuments"
table = dynamodb.Table(table_name)

# ------------------- Cognito OAuth Setup -------------------
from dotenv import load_dotenv
import os

load_dotenv()  # load values from .env

COGNITO_DOMAIN = os.getenv("COGNITO_DOMAIN")
USER_POOL_ID = os.getenv("USER_POOL_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")

oauth = OAuth(app)
oauth.register(
    name='oidc',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=f'https://cognito-idp.ap-south-1.amazonaws.com/{USER_POOL_ID}/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email phone'}
)

# ------------------- Login Required Decorator -------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ------------------- Routes -------------------
@app.route('/')
def home():
    session['user'] = {
        "email": "testuser@example.com",
        "name": "Test User"
    }
    return redirect('/static/index.html')


@app.route('/api/user')
@login_required
def get_user():
    """Returns currently logged-in user info"""
    return jsonify(session.get('user'))

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('../static', filename)

# ------------------- S3 Presigned URL -------------------
@app.route('/generate_presigned', methods=['POST'])
@login_required
def generate_presigned():
    data = request.get_json()
    filename = data.get('filename')
    username = session.get('user', {}).get('email', 'anonymous')
    s3_key = f"{username}/{filename}"
    
    if not filename:
        return jsonify({'error': 'Filename is required'}), 400
    try:
        presigned_url = s3.generate_presigned_url(
            'put_object',
            Params={'Bucket': S3_BUCKET, 'Key': s3_key, 'ContentType': 'application/octet-stream'},
            ExpiresIn=300
        )
        file_url = f"https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{s3_key}"
        return jsonify({'url': presigned_url, 'file_url': file_url})
    except ClientError as e:
        logging.exception("S3 presigned URL generation error:")
        return jsonify({'error': str(e)}), 500

# ------------------- Text Extraction -------------------
@app.route('/extract_text', methods=['POST'])
@login_required
def extract_text():
    data = request.get_json()
    filename = data.get('filename')
    doc_type = data.get('doc_type')
    username = session.get('user', {}).get('email', 'anonymous')
    s3_key = f"{username}/{filename}"

    if not filename or not doc_type:
        return jsonify({'error': 'Filename and document type are required'}), 400

    try:
        textract_resp = textract.detect_document_text(Document={'S3Object': {'Bucket': S3_BUCKET, 'Name': s3_key}})
        extracted_text = '\n'.join([b['Text'] for b in textract_resp['Blocks'] if b['BlockType'] == 'LINE'])

        rek_texts = []
        if doc_type in ['voter', 'driving', 'pan']:
            rek_resp = rekognition.detect_text(Image={'S3Object': {'Bucket': S3_BUCKET, 'Name': s3_key}})
            rek_texts = [t['DetectedText'] for t in rek_resp['TextDetections']]

        if doc_type == "bank":
                result = detect_fraud_bank(extracted_text, rek_texts)
                flags = result["flags"]
                summary = result["summary"]

        elif doc_type in ["voter", "driving"]:
            flags, summary = detect_id(extracted_text, rek_texts, doc_type)
        elif doc_type == "pan":
            flags, summary = detect_pan(extracted_text, rek_texts)
        else:
            flags, summary = [], None

        store_success = store_data(username, filename, doc_type, flags, summary)
        send_alert(username, filename, flags)


        return jsonify({
            'text': extracted_text.strip(),
            'fraud_flags': flags,
            'summary': summary
        })

    except Exception as e:
        logging.exception("Extraction error:")
        return jsonify({'error': str(e)}), 500

# ------------------- PDF Report -------------------
@app.route('/download_report', methods=['POST'])
@login_required
def download_report():
    data = request.get_json()
    filename = data.get('filename', 'unknown.pdf')
    doc_type = data.get('doc_type', 'unknown')
    fraud_flags = data.get('fraud_flags', [])
    summary = data.get('summary', {})

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("📄 <b>Loan Document Fraud Report</b>", styles['Title']))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>Document Name:</b> {filename}", styles['Normal']))
    story.append(Paragraph(f"<b>Document Type:</b> {doc_type.title()}", styles['Normal']))
    story.append(Spacer(1, 12))

    story.append(Paragraph("<b>🛑 Detected Issues:</b>", styles['Heading3']))
    if fraud_flags:
        for flag in fraud_flags:
            story.append(Paragraph(f"❌ {flag}", styles['Normal']))
    else:
        story.append(Paragraph("✅ No red flags detected.", styles['Normal']))
    story.append(Spacer(1, 12))

    if doc_type == "bank" and summary:
        story.append(Paragraph("<b>📊 Bank Summary:</b>", styles['Heading3']))
        for key, value in summary.items():
            story.append(Paragraph(f"{key.replace('_',' ').title()}: ₹{value}", styles['Normal']))
        story.append(Spacer(1, 12))

    story.append(Paragraph(f"<i>Generated on: {datetime.now().strftime('%d %b %Y %I:%M %p')}</i>", styles['Normal']))
    doc.build(story)
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name="fraud_report.pdf", mimetype='application/pdf')

# ------------------- Helper Functions -------------------
from decimal import Decimal

def store_data(username, filename, doc_type, fraud_flags, summary=None):
    try:
        # Convert all float values in summary to Decimal
        if summary:
            summary = {k: Decimal(str(v)) for k, v in summary.items()}

        table.put_item(Item={
            'username': username,
            'timestamp': datetime.utcnow().isoformat(),
            'filename': filename,
            'doc_type': doc_type,
            'fraud_flags': fraud_flags,
            'summary': summary or {}
        })
        return True
    except Exception as e:
        logging.exception("DynamoDB store failed:")
        return False

def send_alert(email, filename, fraud_flags):
    if not fraud_flags:
        return
    try:
        sns = boto3.client('sns', region_name='ap-south-1')
        topic_arn = "arn:aws:sns:ap-south-1:465983268993:fraudalert"  # Your topic ARN
        
        message = f"🚨 Loan Document Fraud Detected 🚨\n\nUploaded by: {email}\nFilename: {filename}\n\nDetected Issues:\n- " + "\n- ".join(fraud_flags)
        subject = "LoanGuard Alert: Fraud Flags Detected"
        
        sns.publish(TopicArn=topic_arn, Subject=subject, Message=message)
        print(f"✅ SNS alert sent for {filename}")
    except Exception as e:
        print(f"❌ SNS alert failed: {str(e)}")

# ------------------- Fraud Detection Logic -------------------
def summarize_bank_statement(text):
    summary = {
        "total_credited": 0,
        "total_debited": 0,
        "total_salary": 0,
        "total_emi": 0,
        "total_atm": 0,
        "total_upi_credit": 0,
        "total_upi_debit": 0
    }
    for line in text.strip().split('\n'):
        line_lower = line.lower()
        amounts = re.findall(r'\d[\d,]*\.?\d*', line)
        if not amounts:
            continue
        try:
            amt = float(amounts[-1].replace(',', '').strip())
        except ValueError:
            continue
        if "atm withdraw" in line_lower or "atw" in line_lower:
            summary["total_atm"] += amt
            summary["total_debited"] += amt
        elif "salary" in line_lower:
            summary["total_salary"] += amt
            summary["total_credited"] += amt
        elif "emi" in line_lower:
            summary["total_emi"] += amt
            summary["total_debited"] += amt
        elif "upi paid" in line_lower or "upi debit" in line_lower:
            summary["total_upi_debit"] += amt
            summary["total_debited"] += amt
        elif "upi received" in line_lower or "upi credit" in line_lower:
            summary["total_upi_credit"] += amt
            summary["total_credited"] += amt
        elif "credit" in line_lower:
            summary["total_credited"] += amt
        elif "debit" in line_lower:
            summary["total_debited"] += amt
    return summary

import re

def detect_fraud_bank(text, rek_texts):
    flags = []
    lower_text = text.lower()
    required_fields = ["account number", "ifsc", "bank", "statement date"]

    # ---- FIELD CHECK ----
    for field in required_fields:
        if field not in lower_text:
            flags.append(f"Missing '{field.title()}' field.")

    # ---- TRANSACTION TABLE CHECK ----
    if not any(k in lower_text for k in ["credit", "debit", "balance", "amount"]):
        flags.append("No transaction table found (Credit/Debit/Balance missing).")

    # ---- DATE PATTERN CHECK ----
    date_matches = re.findall(r'\d{1,2}[-/]\w{3,}[-/]\d{2,4}', text)
    if not date_matches:
        flags.append("No valid date patterns found.")

    # ---- BANK NAME CHECK ----
    known_banks = ['sbi', 'hdfc', 'icici', 'axis', 'kotak', 'pnb', 'canara', 'bank of baroda', 'yes bank', 'idfc', 'bank']
    full_text = (text + ' ' + ' '.join(rek_texts)).lower()
    if not any(bank in full_text for bank in known_banks):
        flags.append("Bank name not detected (possible tampering).")

    # ---- IFSC AND BANK MATCH CHECK ----
    ifsc_match = re.search(r'\b([A-Z]{4})\d{7}\b', text)
    bank_match = re.search(r'bank[:\s]*([a-zA-Z\s]+)', text, re.IGNORECASE)
    if ifsc_match and bank_match:
        ifsc_code = ifsc_match.group(1).lower()
        bank_name = bank_match.group(1).lower()
        bank_keywords = {
            'hdfc': 'hdfc', 'icic': 'icici', 'sbin': 'sbi', 'axis': 'axis',
            'kotk': 'kotak', 'pnb': 'pnb', 'cnrb': 'canara', 'barb': 'baroda',
            'yesb': 'yes', 'idfb': 'idfc'
        }
        expected_bank_keyword = bank_keywords.get(ifsc_code[:4], '')
        if expected_bank_keyword and expected_bank_keyword not in bank_name:
            flags.append(f"❌ IFSC code ({ifsc_code.upper()}) does not match mentioned bank name ({bank_name.title()}).")

    # ---- FRAUD SCORING LOGIC ----
    fraud_score = 0

    # Weighting logic: assign severity per flag type
    for flag in flags:
        if "missing" in flag.lower():
            fraud_score += 20
        elif "not detected" in flag.lower():
            fraud_score += 25
        elif "ifsc" in flag.lower():
            fraud_score += 30
        elif "no valid date" in flag.lower():
            fraud_score += 15
        else:
            fraud_score += 10

    # Cap the score at 100
    fraud_score = min(fraud_score, 100)

    # Determine overall status
    if fraud_score >= 70:
        status = "❌ High Risk"
    elif fraud_score >= 40:
        status = "⚠️ Medium Risk"
    else:
        status = "✅ Low Risk"

    # ---- FINAL SUMMARY ----
    summary = summarize_bank_statement(text)
    result = {
        "flags": flags,
        "fraud_score": fraud_score,
        "status": status,
        "summary": summary
    }

    return result

def detect_id(text, rek_texts, doc_type):
    flags = []
    combined_text = (text + " " + " ".join(rek_texts)).lower()
    required_keywords = ["dob"]
    if doc_type == "voter":
        required_keywords += ["voter", "epic"]
    elif doc_type == "driving":
        required_keywords += ["driving", "license"]
    for kw in required_keywords:
        if kw not in combined_text:
            flags.append(f"Missing '{kw.upper()}' keyword.")
    return flags, None

def detect_pan(text, rek_texts):
    flags = []
    combined_text = (text + " " + " ".join(rek_texts)).upper()
    required_keywords = ["PAN", "INCOME TAX", "DOB"]
    for kw in required_keywords:
        if kw not in combined_text:
            flags.append(f"Missing '{kw}' keyword.")
    pan_matches = re.findall(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b', combined_text)
    if not pan_matches:
        flags.append("PAN number not detected or invalid format.")
    elif len(pan_matches) > 1:
        flags.append(f"Multiple PAN numbers detected: {', '.join(pan_matches)}")
    return flags, None

# ------------------- Run App -------------------
if __name__ == '__main__':
    
    app.run(host='0.0.0.0', port=5000)