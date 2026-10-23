# Password Spray Analyzer

A beginner Python project that analyzes sample Microsoft Entra sign-in events and flags source IPs with failed sign-ins against multiple distinct accounts.

## How it works

1. Filters events with `ResultType` equal to `"50126"`.
2. Counts failed sign-ins per user, grouped by source IP.
3. Returns IPs whose distinct-account count meets or exceeds a configurable threshold.

The output preserves each flagged IP’s users and their failure counts.

## Run the script

Requires Python 3. No external packages are needed.

```bash
python main.py
```

The example uses:

```python
threshold = 2
```

This means at least **2 distinct accounts with failures from the same IP**, rather than 2 total failed attempts.

## Expected output

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

## Scope

- Uses fictional Entra-style sample data.
- Processes only `"50126"` events.
- Evaluates all supplied events together without a time window.
- Flags possible password spraying for investigation, rather than confirming an attack.

## Learning goals

Built with guidance while practicing loops, filtering, nested dictionaries, counting, and configurable thresholds.