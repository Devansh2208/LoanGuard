import boto3
from botocore.exceptions import ClientError

# Use CLI-configured credentials
textract = boto3.client('textract', region_name='ap-south-1')

# Your S3 file
S3_BUCKET = 'loan-document-upload-bucket'
FILE_NAME = 'dummy_statement.pdf'  # Make sure it exists in S3

try:
    response = textract.detect_document_text(
        Document={
            'S3Object': {
                'Bucket': S3_BUCKET,
                'Name': FILE_NAME
            }
        }
    )

    print("✅ Detected Text:\n")
    for block in response['Blocks']:
        if block['BlockType'] == 'LINE':
            print(block['Text'])

except ClientError as e:
    print("❌ AWS Client Error:", e)
except Exception as e:
    print("❌ General Error:", e)
