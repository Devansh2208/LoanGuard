# generate_bank_samples.py

from fpdf import FPDF
import os

# Create output folder
output_folder = "sample_bank_statements"
os.makedirs(output_folder, exist_ok=True)

# Sample bank statements with issues
bank_samples = [
    {
        "filename": "bank_missing_ifsc.pdf",
        "content": """Account Number: 1234567890
Bank: HDFC Bank
Statement Date: 01-Sep-2025 to 30-Sep-2025

Transactions:
01-Sep-2025 | Credit | 50,000
05-Sep-2025 | Debit | 5,000
10-Sep-2025 | Debit | 2,500
"""
    },
    {
        "filename": "bank_duplicate_amounts.pdf",
        "content": """Account Number: 9876543210
IFSC: HDFC0001234
Bank: HDFC Bank
Statement Date: 01-Sep-2025 to 30-Sep-2025

Transactions:
01-Sep-2025 | Credit | 50,000
02-Sep-2025 | Credit | 50,000
05-Sep-2025 | Debit | 10,000
06-Sep-2025 | Debit | 10,000
"""
    },
    {
        "filename": "bank_invalid_date.pdf",
        "content": """Account Number: 1112223334
IFSC: ICIC0005678
Bank: ICICI Bank
Statement Date: 01/09/2025 to 30/09/2025

Transactions:
01-09-2025 | Credit | 40,000
05/09/2025 | Debit | 4,000
10-13-2025 | Debit | 2,500
"""
    },
    {
        "filename": "bank_no_transactions.pdf",
        "content": """Account Number: 5556667778
IFSC: SBI0001112
Bank: State Bank of India
Statement Date: 01-Sep-2025 to 30-Sep-2025

Transactions:
-- No transactions --
"""
    },
    {
        "filename": "bank_wrong_bank.pdf",
        "content": """Account Number: 4445556667
IFSC: HDFC0009999
Bank: ICICI Bank
Statement Date: 01-Sep-2025 to 30-Sep-2025

Transactions:
01-Sep-2025 | Credit | 60,000
05-Sep-2025 | Debit | 15,000
10-Sep-2025 | Debit | 5,000
"""
    }
]

# Generate PDFs
for sample in bank_samples:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    for line in sample["content"].split("\n"):
        pdf.cell(0, 8, txt=line, ln=True)
    pdf.output(os.path.join(output_folder, sample["filename"]))

print(f"✅ Sample bank statement PDFs created in '{output_folder}' folder.")
