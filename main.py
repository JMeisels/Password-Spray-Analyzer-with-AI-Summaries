import json
import requests
import os
from dotenv import load_dotenv

load_dotenv()
llm_api_key = os.getenv("OpenAI_API_Key")

# MOCK DATA
events = [
    {
        "TimeGenerated": "2026-10-22T14:00:00Z",
        "UserPrincipalName": "alex@example.com",
        "IPAddress": "203.0.113.10",
        "ResultType": "50126"
    },
    {
        "TimeGenerated": "2026-10-22T14:01:00Z",
        "UserPrincipalName": "sam@example.com",
        "IPAddress": "203.0.113.10",
        "ResultType": "50126"
    },
    {
        "TimeGenerated": "2026-10-22T14:02:00Z",
        "UserPrincipalName": "jordan@example.com",
        "IPAddress": "203.0.113.10",
        "ResultType": "50126"
    },
    {
        "TimeGenerated": "2026-10-22T14:03:00Z",
        "UserPrincipalName": "alex@example.com",
        "IPAddress": "203.0.113.10",
        "ResultType": "50126"
    },
    {
        "TimeGenerated": "2026-10-22T14:04:00Z",
        "UserPrincipalName": "taylor@example.com",
        "IPAddress": "203.0.113.10",
        "ResultType": "0"
    },
    {
        "TimeGenerated": "2026-10-22T14:05:00Z",
        "UserPrincipalName": "morgan@example.com",
        "IPAddress": "198.51.100.20",
        "ResultType": "50126"
    },
    {
        "TimeGenerated": "2026-10-22T14:06:00Z",
        "UserPrincipalName": "morgan@example.com",
        "IPAddress": "198.51.100.20",
        "ResultType": "50126"
    },
    {
        "TimeGenerated": "2026-10-22T14:07:00Z",
        "UserPrincipalName": "morgan@example.com",
        "IPAddress": "198.51.100.20",
        "ResultType": "50126"
    },
    {
        "TimeGenerated": "2026-10-22T14:08:00Z",
        "UserPrincipalName": "casey@example.com",
        "IPAddress": "192.0.2.30",
        "ResultType": "50126"
    },
    {
        "TimeGenerated": "2026-10-22T14:09:00Z",
        "UserPrincipalName": "riley@example.com",
        "IPAddress": "192.0.2.30",
        "ResultType": "50126"
    },
    {
        "TimeGenerated": "2026-10-22T14:10:00Z",
        "UserPrincipalName": "jamie@example.com",
        "IPAddress": "192.0.2.30",
        "ResultType": "0"
    }
]

# Threshold of amount of accounts a given IP address has failed to log into.
threshold = 2

# Function that filters all logs where the failure was due to incorrect credentials and where the IP address has failed to log into a minimum of 2 accounts (the threshold).
def password_spray_assessment(events, threshold):
    failed_password_events = []
    failure_counts_by_user_ip = {}
    suspicious_ip_and_accounts = {}
    for event in events:
        if event['ResultType'] == '50126':
            failed_password_events.append(event)
    for log in failed_password_events:
            if log['IPAddress'] not in failure_counts_by_user_ip:
                  failure_counts_by_user_ip[log['IPAddress']] = {}
            if log['IPAddress'] in failure_counts_by_user_ip:
                if log['UserPrincipalName'] not in failure_counts_by_user_ip[log['IPAddress']]:
                    failure_counts_by_user_ip[log['IPAddress']][log['UserPrincipalName']] = 1
                elif log['UserPrincipalName'] in failure_counts_by_user_ip[log['IPAddress']]:
                    failure_counts_by_user_ip[log['IPAddress']][log['UserPrincipalName']] += 1
    for object in failure_counts_by_user_ip:
        if len(failure_counts_by_user_ip[object]) >= threshold:
            suspicious_ip_and_accounts[object] = failure_counts_by_user_ip[object]
    return suspicious_ip_and_accounts

findings = password_spray_assessment(events, threshold)

#Converts the findings to JSON in preperation to export to an LLM API.
findings_json = json.dumps(findings)

#Instructions to the LLM using an f string to incorporate mutable upstream code.
summary_instructions = f"Here I am providing you with aggregated findings for IP addresses that have attempted to log into the minimum {threshold} amount of distinct accounts or more, with a ResultType of '50126' as per Entra logs. Please summarize the findings in no more than 3 sentences, using only the supplied evidence. Describe possible spraying without claiming confirmed compromise."

#LLM API Header: Intertwines the authorization/API key along with the data type that's going to follow in the body.
headers = {
     "Authorization": f"Bearer {llm_api_key}",
     "Content-Type": "application/json"
}

#LLM API body: Tells the LLM Model what model to process the input and instructions through.
body = {
    "model": "gpt-6.1-sol",
    "instructions": summary_instructions,
    "input": findings_json
}

#Sends the body and headers through the URL using the API (requests) package.
try:
    response = requests.post(
        url="https://api.openai.com/v1/responses",
        headers=headers,
        json=body,
        timeout=60
    )
    #Loads the response as a Python structure, references the text output of the instructions provided and prints it for the user/SOC analyst.
    if response.status_code == 200:
        response_data = json.loads(response.text)
        message = response_data['output'][0]['content'][0]['text']
        print(message)
    elif response.status_code == 401:
        print("Authentication failed. Check your API key.")
    else:
         print(f"API failed. {response.status_code}: {response.text}")
except requests.exceptions.Timeout:
     print("The request timed out.")
except requests.exceptions.ConnectionError:
     print("Couldn't connect to the API")