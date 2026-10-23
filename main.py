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

threshold = 2

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

print(password_spray_assessment(events, threshold))