# Trufflehog4

Integrates with TruffleHog to detect secrets across multiple platforms including GitHub repositories, Docker containers, GitHub Container Registry (GHCR), and Postman workspaces. Scans in mass rather than one particular target at a time. 

## Overview

This tool extends TruffleHog's capabilities by providing:

- Multi-platform scanning support
- Batch processing capabilities
- Size-based filtering
- Time-based filtering
- Fork exclusion options
- Docker image management
- Postman workspace scanning

## Features

- **GitHub Scanning**
  - Scan organization repositories
  - Scan user repositories
  - Process specific repositories
  - Filter by repository size
  - Filter by last update time
  - Exclude forked repositories

- **Docker Hub Scanning**
  - Scan organization images
  - Process specific images
  - Support for Schema 1 to Schema 2 conversion
  - Layer extraction capabilities

- **GitHub Container Registry (GHCR) Scanning**
  - Scan organization containers
  - Process specific containers
  - Automated authentication

- **Postman Workspace Scanning**
  - Scan all workspaces
  - Scan specific workspace by ID
  - Search workspaces by name

## Installation

1. Ensure you have Go installed on your system
2. Install required dependencies:
   ```bash
   # Install TruffleHog
   go install github.com/trufflesecurity/trufflehog/v3@latest

   # Install Docker (for container scanning)
   # Follow instructions at https://docs.docker.com/get-docker/

   # Install Skopeo (for Docker Schema 1 conversion)
   # For Ubuntu/Debian:
   sudo apt-get install skopeo
   # For MacOS:
   brew install skopeo
   ```

3. Clone this repository:
   ```bash
   git clone https://github.com/fr4nk3nst1ner/trufflehog4.git
   cd trufflehog4
   ```

## Usage

### Basic Commands

```bash
go run trufflehog4.go <command> [options]
```

### Available Commands

- `github`: Scan GitHub repositories
- `ghcr`: Scan GitHub Container Registry images
- `docker`: Scan Docker Hub images
- `postman`: Scan Postman workspaces

### Common Options

```bash
  --github-org string      Name of the GitHub organization
  --max-repo-size int     Maximum repository size in MB
  --token string          GitHub/Postman Personal Access Token
  --user string           Process repositories for a specific user
  --repo string           Process a specific repository URL
  --user-list string      File with a list of usernames to process
  --verify               Run trufflehog with verification
  --only-verified        Run trufflehog with --only-verified option
  --no-fork             Exclude forked repositories
  --time-limit int      Limit repositories to those updated within the last N years
```

### Example Commands

1. Scan GitHub Organization:
```bash
go run trufflehog4.go github --github-org myorg --trufflehog --token YOUR_GITHUB_TOKEN
```

2. Scan Docker Hub Organization:
```bash
go run trufflehog4.go docker --scan-org myorg --token YOUR_DOCKER_TOKEN
```

3. Scan GHCR Images:
```bash
go run trufflehog4.go ghcr --github-org myorg --token YOUR_GITHUB_TOKEN
```

4. Scan Postman Workspaces:
```bash
go run trufflehog4.go postman --token YOUR_POSTMAN_TOKEN
```

5. Scan Specific Repository:
```bash
go run trufflehog4.go github --repo https://github.com/org/repo.git --trufflehog
```

6. Scan Multiple Users from File:
```bash
go run trufflehog4.go github --user-list users.txt --trufflehog
```

## Security Considerations

- Store tokens securely and never commit them to version control
- Use appropriate access tokens with minimal required permissions
- Be mindful of rate limits when scanning large organizations
- Consider using `--verify` for more accurate results but careful as it can trigger alers
- Clean up downloaded images after scanning, default uses `--retain-image=false`

## License

MIT License

Copyright (c) 2024 Jonathan Stines

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Disclaimer

This tool is meant for security testing purposes only. Always ensure you have appropriate authorization before scanning any repositories or containers.
