import boto3
import os
from botocore.exceptions import ClientError

def get_assumed_role_session(role_arn, session_name="MySession", external_id=None,
                             duration_seconds=900, region_name=None,
                             mfa_serial_number=None, mfa_token=None):
    """
    Gets a boto3 session using AssumeRole credentials.

    Args:
        role_arn (str): The ARN of the IAM role to assume.
        session_name (str, optional): An identifier for the assumed role session.
        external_id (str, optional): An external ID required by the role's trust policy.
        duration_seconds (int, optional): The duration, in seconds, of the role session. (900-43200 for console, 900-3600 for API)
        region_name (str, optional): AWS region.  If None, uses the default region from your AWS config/environment.
        mfa_serial_number (str, optional): The identification number of the MFA device.
        mfa_token (str, optional): The time-based one-time password (TOTP) from the MFA device.

    Returns:
        boto3.Session: A boto3 session object using the assumed role credentials, or None on error.

    Raises:
        ClientError: If there's an issue with the AssumeRole call (e.g., invalid ARN, permissions).
        Exception: For other unexpected errors.
    """
    try:
        # Use environment variables or AWS config file for base credentials.
        sts_client = boto3.client('sts', region_name=region_name)

        assume_role_kwargs = {
            'RoleArn': role_arn,
            'RoleSessionName': session_name,
            'DurationSeconds': duration_seconds
        }
        if external_id:
            assume_role_kwargs['ExternalId'] = external_id
        if mfa_serial_number and mfa_token:
           assume_role_kwargs['SerialNumber'] = mfa_serial_number
           assume_role_kwargs['TokenCode'] = mfa_token

        response = sts_client.assume_role(**assume_role_kwargs)

        credentials = response['Credentials']
        return boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=region_name
        )

    except ClientError as e:
        print(f"Error assuming role: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None
def s3_list_buckets(session):
    """Lists S3 buckets using a given boto3 session."""
    if not session:
        return []  # Or raise an exception, depending on your error handling

    s3 = session.resource('s3') # Use resource, not client.
    bucket_names = []
    try:
        for bucket in s3.buckets.all():  # Iterate directly over buckets
            bucket_names.append(bucket.name)
    except ClientError as e:
        print(f"Error listing buckets: {e}")
        # Consider re-raising the exception or returning None, depending on needs.
    return bucket_names



def s3_upload_file(session, file_path, bucket_name, object_key=None):
    """
    Uploads a file to an S3 bucket.

    Args:
        session:  boto3 session (with assumed role creds, if needed)
        file_path: Path to the local file.
        bucket_name: Name of the S3 bucket.
        object_key: S3 object key.  If None, uses the file name.

    Returns:
        True if successful, False otherwise.
    """

    if object_key is None:
        object_key = os.path.basename(file_path)

    s3 = session.resource('s3')  # Use resource
    try:
        s3.Bucket(bucket_name).upload_file(file_path, object_key)
        print(f"File '{file_path}' uploaded to '{bucket_name}/{object_key}'")
        return True
    except ClientError as e:
        print(f"Error uploading file: {e}")
        return False
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        return False
    except Exception as e: # Catch any other exceptions
        print(f"An unexpected error occurred: {e}")
        return False


def s3_download_file(session, bucket_name, object_key, file_path):
    """Downloads a file from S3."""

    s3 = session.resource('s3') #Use resource
    try:
        s3.Bucket(bucket_name).download_file(object_key, file_path)
        print(f"File '{object_key}' downloaded from '{bucket_name}' to '{file_path}'")
        return True
    except ClientError as e:
        print(f"Error downloading file: {e}")
        if e.response['Error']['Code'] == '404':  # Handle 404 specifically
           print("The object does not exist.")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False

def s3_delete_object(session, bucket_name, object_key):
  """Deletes an object from S3"""
  s3 = session.resource('s3')

  try:
    s3.Object(bucket_name, object_key).delete()
    print(f"Object '{object_key}' deleted from bucket '{bucket_name}'.")
    return True
  except ClientError as e:
    print(f"Error deleting object: {e}")
    return False
  except Exception as e:
    print(f"An unexpected error occurred: {e}")
    return False

def s3_object_exists(session, bucket_name, object_key):
    """Checks if an object exists in S3."""
    s3 = session.resource('s3')
    try:
        s3.Object(bucket_name, object_key).load()  # Try to load object metadata
        return True # Object exists
    except ClientError as e:
        if e.response['Error']['Code'] == "404":
            return False  # Object does not exist
        else:
            print(f"Error checking object existence: {e}")
            return False  # Assume it doesn't exist for safety, or raise
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False

def main():
    # --- Configuration ---
    role_arn = "arn:aws:iam::123456789012:role/YourAssumedRole"  # Replace with your role ARN
    external_id = "YourExternalId"  # Replace or set to None if not needed
    bucket_name = "your-bucket-name"      # Replace with your bucket name
    region = "us-east-1"  # Replace with your region, or leave as None for default

    # --- Assume Role (Optional MFA) ---
    # For MFA, uncomment and provide your MFA serial number and token:
    # mfa_serial = "arn:aws:iam::123456789012:mfa/your-user"  # Replace
    # mfa_token = "123456"  # Replace with the current token from your MFA device
    mfa_serial= None
    mfa_token = None

    session = get_assumed_role_session(
        role_arn,
        external_id=external_id,
        region_name=region,
        mfa_serial_number=mfa_serial,
        mfa_token=mfa_token
    )

    if not session:
        print("Failed to assume role. Exiting.")
        return

    # --- S3 Operations ---

    # List Buckets
    buckets = s3_list_buckets(session)
    print("Buckets:", buckets)

    # Upload a File
    file_to_upload = "example.txt"  # Create a file named example.txt
    with open(file_to_upload, "w") as f:
      f.write("This is a test file for S3 upload.")

    if s3_upload_file(session, file_to_upload, bucket_name):
       print("Upload successful.")
    else:
       print("Upload failed.")

    # Check If Object Exists
    object_key = "example.txt"
    if s3_object_exists(session, bucket_name, object_key):
        print(f"Object '{object_key}' exists in bucket '{bucket_name}'.")
    else:
        print(f"Object '{object_key}' does not exist in bucket '{bucket_name}'.")

    # Download the File
    downloaded_file = "downloaded_example.txt"
    if s3_download_file(session, bucket_name, object_key, downloaded_file):
      print("Download sucessful.")
    else:
      print("Download failed.")

    # Delete the object
    if s3_delete_object(session, bucket_name, object_key):
      print("Deletion successful.")
    else:
      print("Deletion failed")

    # Verify Deletion (should now be False)
    if s3_object_exists(session, bucket_name, object_key):
        print(f"Object '{object_key}' exists in bucket '{bucket_name}'.")
    else:
        print(f"Object '{object_key}' does not exist in bucket '{bucket_name}'.")

if __name__ == "__main__":
    main()