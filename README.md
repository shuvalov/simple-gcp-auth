# Simple GCP Auth

This package provides a simplified way to fetch credentials for Google Cloud Platform.

## Installation

```bash
pip install simple-gcp-auth
```

## Usage

```python
from simple_gcp_auth import from_interactive_user

credentials = from_interactive_user()
# Now you can use the credentials with your GCP clients
