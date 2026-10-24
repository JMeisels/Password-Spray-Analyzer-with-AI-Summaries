# Password Spray Analyzer

A beginner Python project that analyzes sample Microsoft Entra sign-in events, flags potential password spraying, and generates an AI summary using the OpenAI API.

## How it works

1. Filters events with `ResultType` equal to `"50126"`.
2. Counts failed sign-ins per user, grouped by source IP.
3. Selects IPs whose distinct-account count meets or exceeds a configurable threshold.
4. Sends the aggregated findings and summary instructions to OpenAI.
5. Extracts and prints the generated summary.

Python handles detection. AI summarizes the findings.

## Setup

Requires Python 3, an OpenAI API key, and API credits. API requests incur usage charges.

Install the dependencies:

```bash
python -m pip install requests python-dotenv
```

Create a `.env` file in the project folder:

```dotenv
OpenAI_API_Key=your_api_key_here
```

Add this line to `.gitignore` to keep the key out of Git:

```gitignore
.env
```

Never commit your actual API key.

## Run the script

```bash
python main.py
```

The example uses:

```python
threshold = 2
```

This means at least **2 distinct accounts with failures from the same IP**, rather than 2 total failed attempts.

## Example findings

The sample data produces these findings before AI summarization:

```python
{
    "203.0.113.10": {
        "alex@example.com": 2,
        "sam@example.com": 1,
        "jordan@example.com": 1
    },
    "192.0.2.30": {
        "casey@example.com": 1,
        "riley@example.com": 1
    }
}
```

## Example AI summary

> IP 203.0.113.10 recorded 4 failed sign-in attempts across 3 distinct accounts, while 192.0.2.30 recorded 2 across 2 distinct accounts. These multi-account failures may indicate password spraying, but the supplied evidence does not establish compromise.

Summary wording may vary between runs. Check generated statements against the findings.

## Scope

- Uses fictional Entra-style sample data.
- Processes only `"50126"` events.
- Evaluates all supplied events together without a time window.
- Sends aggregated findings to the OpenAI Responses API using `gpt-6.1-sol`.
- Flags possible password spraying for investigation, rather than confirming an attack.
- Is a learning prototype, not a production detection system.

## Learning goals

Built with guidance while practicing:

- Loops, filtering, and nested dictionaries.
- Counting and configurable thresholds.
- JSON serialization and response parsing.
- Environment variables and API authentication.
- HTTP requests, headers, and request bodies.
- AI instructions and evidence-based summarization.
- Git and GitHub.