# WHOIS API Lambda

A refactored WHOIS API service deployed as an AWS Lambda function, providing WHOIS data retrieval for domains with LLM-powered parsing.

## Features

- Retrieve raw WHOIS data
- Parse WHOIS data into structured JSON
- Bulk WHOIS lookups
- List available TLDs
- Health check endpoint

## Prerequisites

- Go 1.26.1+
- AWS CLI configured
- Terraform 1.0.0+
- OpenRouter API key (for LLM parsing)

## Setup

1. Clone the repository
2. Set up environment variables:
   ```bash
   cp .env.example .env  # If exists, or set OPENROUTER_API_KEY
   ```

3. Initialize Terraform:
   ```bash
   make setup
   ```

## Build and Deploy

```bash
make deploy
```

This builds the Lambda binary, packages it, and deploys via Terraform.

## API Endpoints

- `GET /whois-api/ping` - Health check
- `GET /whois-api/available-tlds` - Get supported TLDs
- `POST /whois-api/whois/raw` - Get raw WHOIS data
- `POST /whois-api/whois` - Get parsed WHOIS data
- `POST /whois-api/whois/bulk` - Bulk WHOIS lookups

## Testing

```bash
make test-api
```

## Development

```bash
make dev  # Format, vet, lint, test, build
```