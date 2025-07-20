# Simple GCP Auth

This package provides a simplified way to fetch credentials for Google Cloud Platform.

## Installation

```bash
pip install simple-gcp-auth
```

## Usage

```python
from simple-gcp-auth import from_interactive_user

credentials = from_interactive_user()
# Authenticate via interactive web-based logon

```python
from simple-gcp-auth import from_manual_flow

credentials = from_manual_flow()
# Authenticate via web link. Can be performed on another device
