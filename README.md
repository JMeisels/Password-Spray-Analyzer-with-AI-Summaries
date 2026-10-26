# Password Spray Analyzer | Python, Docker & AI

A Python-based cybersecurity project that analyzes sample Microsoft Entra ID sign-in events, identifies potential password-spraying activity, and generates concise, evidence-based investigation summaries using the OpenAI API.

The application supports execution locally or inside a Docker container.

*Disclaimer: This project was written manually without the use of AI with the exception of the documentation.
## Overview

Password spraying is an authentication attack technique in which an attacker attempts to access multiple accounts using a small number of passwords.

This project demonstrates how Python can be used to identify suspicious authentication patterns and how AI can assist a security analyst in summarizing the findings.

**Python performs the detection. AI summarizes the results.**

## Features

- Filters Microsoft Entra-style sign-in events for authentication failure code `50126`.
- Groups failed authentication attempts by source IP address and user account.
- Counts distinct accounts targeted by each IP address.
- Uses a configurable threshold to identify potential password-spraying activity.
- Sends aggregated findings to the OpenAI Responses API for summarization.
- Produces concise, evidence-based summaries without assuming confirmed compromise.
- Supports Docker containerization for portable execution.
- Uses environment variables to separate API credentials from application code.

## How It Works

1. **Event filtering:** Python identifies sign-in events with `ResultType` equal to `50126`, indicating invalid credentials.
2. **Aggregation:** Failed authentication attempts are grouped by source IP and account.
3. **Threshold evaluation:** IP addresses targeting at least the configured number of distinct accounts are flagged.
4. **AI enrichment:** Aggregated findings are serialized into JSON and submitted to the OpenAI Responses API.
5. **Summary generation:** The application prints an investigation summary based on the supplied evidence.

The current default threshold is:

```python
threshold = 2
```

This means an IP must have authentication failures against at least two distinct accounts. Multiple failures against just one account do not satisfy this threshold.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python 3 | Detection logic, data processing, API integration |
| Microsoft Entra ID | Source format for simulated sign-in events |
| OpenAI Responses API | AI-assisted investigation summaries |
| Requests | HTTP communication with the API |
| python-dotenv | Local environment variable management |
| Docker | Application containerization |
| Git and GitHub | Version control and source code management |

## Project Structure

```text
Password-Spray-Analyzer-with-AI-Summaries/
├── main.py
├── requirements.txt
├── Dockerfile
├── .dockerignore
├── .gitignore
└── README.md
```

**File descriptions:**

- `main.py`: Detection logic, sample events, and AI integration.
- `requirements.txt`: Python dependencies.
- `Dockerfile`: Instructions for building the container image.
- `.dockerignore`: Excludes unnecessary files and local credentials from Docker's build context.
- `.gitignore`: Prevents local credentials and virtual-environment files from being tracked by Git.
- `README.md`: Project documentation.

## Prerequisites

To run the application locally, you need:

- Python 3
- An OpenAI API key with available API credits
- Internet access for the OpenAI API request

To run the containerized version, you need Docker installed and running.

**Note:** OpenAI API usage may incur charges.

## Configuration

Create a `.env` file in the project root:

```dotenv
OpenAI_API_Key=your_api_key_here
```

Replace `your_api_key_here` with your own API key.

The variable name must match the name referenced in `main.py`. When using Docker's `--env-file` option, do not include spaces around the `=` sign.

Never commit your actual `.env` file or API key to GitHub.

## Running Locally

Clone the repository:

```bash
git clone https://github.com/JMeisels/Password-Spray-Analyzer-with-AI-Summaries.git
```

Enter the project directory:

```bash
cd Password-Spray-Analyzer-with-AI-Summaries
```

Create a Python virtual environment:

```bash
python3 -m venv .venv
```

Activate it on Linux:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Create the `.env` file using the configuration instructions above.

Run the application:

```bash
python main.py
```

The program processes its built-in sample sign-in events and prints the AI-generated summary.

## Running with Docker

The application can also be executed inside a Docker container without installing its Python dependencies directly into your local environment.

### 1. Build the Docker image

From the project directory:

```bash
sudo docker build -t password-spray-analyzer .
```

Docker uses the project's `Dockerfile` to:

- Start with the `python:3.14-slim` base image.
- Configure `/app` as the working directory.
- Copy the dependency list.
- Install the required Python packages.
- Copy the application files.
- Configure Python to execute `main.py` when the container starts.

### 2. Run the container

After creating your local `.env` file, execute:

```bash
sudo docker run --rm --env-file .env password-spray-analyzer
```

The container executes the password spray analyzer and prints its results to the terminal.

**Command explanation:**

| Argument | Purpose |
|---|---|
| `docker run` | Creates and starts a container |
| `--rm` | Automatically removes the container when it stops |
| `--env-file .env` | Supplies environment variables at runtime |
| `password-spray-analyzer` | Specifies the Docker image |

The `.env` file is not copied into the Docker image. Its variables are supplied when the container starts.

### 3. View Docker images

```bash
sudo docker images
```

### 4. View running containers

```bash
sudo docker ps
```

To view running and stopped containers:

```bash
sudo docker ps -a
```

Because the analyzer executes and exits, its container stops automatically when processing finishes.

Using `--rm` also removes that stopped container while preserving the Docker image.

## Example Detection Results

The fictional sample events include authentication attempts from several IP addresses.

With the current threshold of two distinct accounts, the analyzer identifies:

| Source IP | Failed attempts | Distinct accounts |
|---|---:|---:|
| `203.0.113.10` | 4 | 3 |
| `192.0.2.30` | 2 | 2 |

Another source, `198.51.100.20`, produces three authentication failures against only one account and therefore does not meet the distinct-account threshold.

This distinction helps demonstrate the difference between repeated failures against one account and potential password-spraying activity targeting multiple accounts.

## AI-Generated Summary

The application sends its aggregated findings to the OpenAI Responses API with instructions to produce an evidence-based summary.

An illustrative summary:

> Two source IP addresses met the configured multi-account authentication failure threshold. IP 203.0.113.10 generated four failures across three accounts, while IP 192.0.2.30 generated two failures across two accounts. These patterns warrant further investigation for potential password spraying, although the supplied evidence does not confirm account compromise.

The exact wording may vary between runs.

AI-generated statements should always be validated against the original findings before being used in security investigations.

## Security Considerations

The project incorporates several basic secure development practices:

- **Secret separation:** The API key is stored outside the source code.
- **Git exclusions:** `.gitignore` excludes local credentials and virtual-environment files.
- **Docker exclusions:** `.dockerignore` prevents local credential files, virtual environments, and unnecessary development artifacts from being included in the Docker build context.
- **Runtime configuration:** Docker receives API credentials through environment variables rather than embedding them into the image.
- **Evidence-based summarization:** AI instructions discourage unsupported conclusions about successful compromise.

Environment variables are not a complete secrets-management solution. Anyone with sufficient access to the host or container environment may be able to retrieve them.

Only authorized, appropriately sanitized security telemetry should be submitted to an external AI service.

## Current Limitations

This project is a learning prototype rather than a production-ready detection system.

Currently:

- Authentication data is fictional and embedded directly in `main.py`.
- Real Microsoft Entra ID logs are not retrieved automatically.
- Detection focuses on authentication failure code `50126`.
- The configured threshold is evaluated across the entire supplied sample dataset without a rolling time window.
- No contextual enrichment, such as IP reputation or geolocation, is performed.
- AI summaries require an active OpenAI API connection.
- The application is designed for command-line execution rather than continuous monitoring.

A threshold-based finding identifies activity worth investigating, not definitive evidence of malicious behavior.

## Future Development

Potential enhancements include:

- Integrating Microsoft Graph API to retrieve authorized Entra ID sign-in logs.
- Supporting external JSON log input instead of only embedded sample events.
- Introducing configurable time windows and detection thresholds.
- Adding unit tests for the detection functions.
- Building a GitHub Actions CI pipeline for automated testing and Docker build validation.
- Enriching suspicious IP addresses with threat intelligence.
- Producing structured JSON investigation output for downstream security workflows.

## Learning Objectives

This project was developed as a practical exercise in security engineering, Python development, and application deployment, with AI-assisted guidance.

Core areas of learning include:

- Python functions, loops, conditional logic, and nested dictionaries.
- Authentication log analysis and password-spray detection logic.
- JSON serialization and API response parsing.
- HTTP requests and API authentication.
- AI integration for cybersecurity investigation summaries.
- Python virtual environments and dependency management.
- Git version control and GitHub workflows.
- Docker images, containers, Dockerfiles, and runtime configuration.
- Secure handling of application credentials.

## Disclaimer

This tool is intended for educational use and authorized defensive security analysis.

It does not establish that an attack or compromise occurred, and its output should not be treated as a substitute for a complete security investigation.

---

**Project:** Password Spray Analyzer with AI Summaries

**Repository:** https://github.com/JMeisels/Password-Spray-Analyzer-with-AI-Summaries
