import boto3
import pandas as pd
import io
import time

def run_soc2_audit():
    iam_client = boto3.client("iam")
    print("Requesting IAM Credential Report from AWS...")

    generation_response = iam_client.generate_credential_report()

    while generation_response['State'] != 'COMPLETE':
        print("Waiting for AWS to compile data...")
        time.sleep(2)
        generation_response = iam_client.generate_credential_report()

    print("Report generated! Downloading and parsing data...\n")

    report_response = iam_client.get_credential_report()

    # AWS returns the CSV as raw bytes. We must decode it to a UTF-8 string.
    csv_content = report_response['Content'].decode('utf-8')

    df = pd.read_csv(io.StringIO(csv_content))

    print("=========================================")
    print("   SOC 2 COMPLIANCE AUDIT RESULTS        ")
    print("=========================================\n")

    failures = 0

    for index, row in df.iterrows():
        user = row['user']
        
        # We skip the root account for this specific script as we secured it manually
        if user == '<root_account>':
            continue 
            
        # VULNERABILITY 1: Missing MFA (SOC 2 Logical Access CC6.1)
        if row['mfa_active'] == False or row['mfa_active'] == 'false':
            print(f"[CRITICAL] User '{user}' does not have MFA enabled.")
            failures += 1
            
        # VULNERABILITY 2: Stale or Unused Passwords (Ghost Accounts)
        if row['password_enabled'] == True or row['password_enabled'] == 'true':
            if row['password_last_used'] in ['no_information', 'N/A']:
                 print(f"[WARNING] User '{user}' has console access but has never logged in. Review for deletion.")
                 failures += 1
                 
        # VULNERABILITY 3: Active Programmatic Access Keys
        if row['access_key_1_active'] == True or row['access_key_1_active'] == 'true':
            # In a real enterprise, we would check if 'access_key_1_last_rotated' is > 90 days.
            # Since you just created this key, we will just flag that it exists for testing.
            print(f"[ACTION REQUIRED] User '{user}' has an active access key. Ensure automated rotation is enforced.")
            failures += 1

    print("\n=========================================")
    if failures == 0:
        print("[SUCCESS] 0 Security Violations Found. Environment is SOC 2 Compliant.")
    else:
        print(f"[FAIL] {failures} Security Violations Detected. Please remediate immediately.")
    print("=========================================")

if __name__ == "__main__":
    run_soc2_audit()

