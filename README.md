# Simple GCP Auth

This package provides a simplified way to fetch credentials for Google Cloud Platform.

## Installation

```bash
pip install simple_gcp_auth
```

## Usage

```python
from simple_gcp_auth import from_interactive_user

credentials = from_interactive_user()
# Authenticate via interactive web-based logon

```python
from simple_gcp_auth import from_manual_flow

credentials = from_manual_flow()
# Authenticate via web link. Can be performed on another device
