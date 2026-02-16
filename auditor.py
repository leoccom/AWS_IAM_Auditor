import boto3

# 1. Initialize the Boto3 client for IAM
iam_client = boto3.client('iam')

# 2. Make an API call to AWS to get a list of all users
response = iam_client.list_users()

# 3. Loop through the response and print the usernames
print("Successfully connected! Here are the users in your account:")
for user in response['Users']:
    print(f"- {user['UserName']}")