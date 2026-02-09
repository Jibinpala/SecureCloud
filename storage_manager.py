import os
import boto3
from botocore.exceptions import ClientError
from config import (
    AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 
    AWS_S3_BUCKET, AWS_S3_REGION, 
    UPLOAD_FOLDER, IS_VERCEL
)

class StorageManager:
    def __init__(self):
        self.use_s3 = all([AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_S3_BUCKET])
        self.s3_client = None
        
        if self.use_s3:
            try:
                from config import AWS_S3_ENDPOINT
                self.s3_client = boto3.client(
                    's3',
                    aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                    region_name=AWS_S3_REGION,
                    endpoint_url=AWS_S3_ENDPOINT
                )
                # Verify bucket exists/accessible
                self.s3_client.head_bucket(Bucket=AWS_S3_BUCKET)
                print(f"Cloud storage initialized: S3://{AWS_S3_BUCKET}")
            except Exception as e:
                print(f"S3 initialization failed: {e}. Falling back to local storage.")
                self.use_s3 = False

    def upload_file(self, content, remote_path):
        """Upload file content to S3 or local storage"""
        if self.use_s3:
            try:
                self.s3_client.put_object(
                    Bucket=AWS_S3_BUCKET,
                    Key=remote_path,
                    Body=content
                )
                return True
            except ClientError as e:
                print(f"S3 upload failed: {e}")
                return False
        else:
            # Local fallback (ephemeral if on Vercel)
            local_full_path = os.path.join(UPLOAD_FOLDER, remote_path)
            os.makedirs(os.path.dirname(local_full_path), exist_ok=True)
            with open(local_full_path, 'wb') as f:
                f.write(content)
            return True

    def download_file(self, remote_path):
        """Download file content from S3 or local storage"""
        if self.use_s3:
            try:
                response = self.s3_client.get_object(
                    Bucket=AWS_S3_BUCKET,
                    Key=remote_path
                )
                return response['Body'].read()
            except ClientError as e:
                print(f"S3 download failed: {e}")
                return None
        else:
            local_full_path = os.path.join(UPLOAD_FOLDER, remote_path)
            if os.path.exists(local_full_path):
                with open(local_full_path, 'rb') as f:
                    return f.read()
            return None

    def delete_file(self, remote_path):
        """Delete file from S3 or local storage"""
        if self.use_s3:
            try:
                self.s3_client.delete_object(
                    Bucket=AWS_S3_BUCKET,
                    Key=remote_path
                )
                return True
            except ClientError as e:
                print(f"S3 delete failed: {e}")
                return False
        else:
            local_full_path = os.path.join(UPLOAD_FOLDER, remote_path)
            if os.path.exists(local_full_path):
                os.remove(local_full_path)
            return True

# Global storage manager instance
storage_manager = StorageManager()
