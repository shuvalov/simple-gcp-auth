# Simple GCP Auth

[![PyPI version](https://badge.fury.io/py/simple-gcp-auth.svg)](https://badge.fury.io/py/simple-gcp-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Python package that simplifies the Google Cloud Platform authentication process. It provides easy-to-use functions for fetching user credentials in various environments, abstracting away the complexities of Google's authentication flows.

## Overview

Authenticating with Google Cloud can be challenging, especially when your application needs to run in different environments like a local development machine, a CI/CD pipeline, a Docker container, or a cloud-based notebook like Google Colab. `simple-gcp-auth` provides a set of straightforward helper functions to handle these scenarios gracefully.

## Features

- **Interactive User Flow**: Authenticate on a local machine through a web browser.
- **Credential Caching**: Opt-in to securely cache refresh tokens in your system's native keychain to avoid repeated logins.
- **Forced Re-authentication**: Clear cached credentials to force a new login.
- **Manual Code Flow**: Authenticate in headless environments (like remote servers or Google Colab) by copying a code from a URL.
- **Application Default Credentials (ADC)**: Seamlessly use credentials in standard GCP environments (e.g., GCE, GKE, Cloud Functions).
- **Service Account Impersonation**:
    - Use existing ADC to impersonate a service account.
    - Use an interactive user flow to get credentials for impersonating a service account with Domain-Wide Delegation.
- **Standard Credentials Object**: All functions return a standard `google.oauth2.credentials.Credentials` object, which is compatible with all official Google Cloud client libraries.

## Prerequisites

Before using this package, ensure you have:
1.  A Google Cloud Platform project.
2.  The necessary IAM permissions for your user or service account to access the required resources.

## Installation

Install the package from PyPI:

```bash
pip install simple-gcp-auth
```

## Usage

Here are the different ways you can use `simple-gcp-auth` to get credentials.

---

### 1. For Local Development: `from_interactive_user`

Ideal for scripts and applications running on your local machine where a web browser is available.

```python
from simple_gcp_auth import from_interactive_user
from google.cloud import storage

# This will open a browser window for you to log in.
credentials = from_interactive_user(
    scopes=['https://www.googleapis.com/auth/devstorage.read_only'],
    quota_project_id='your-gcp-project-id'
)

# Use the credentials with a GCP client
storage_client = storage.Client(credentials=credentials, project='your-gcp-project-id')
print("Listing buckets:")
for bucket in storage_client.list_buckets():
    print(bucket.name)
```

#### Caching Credentials

To avoid authenticating every time you run your script, you can enable credential caching. The refresh token will be stored securely in your system's keychain.

```python
credentials = from_interactive_user(
    scopes=['https://www.googleapis.com/auth/devstorage.read_only'],
    quota_project_id='your-gcp-project-id',
    cache_credentials=True  # Enable caching
)
```

The next time you run this code, it will try to use the cached token instead of opening the browser.

To force re-authentication and clear the cached token, use the `force_reauthentication` flag:
```python
credentials = from_interactive_user(
    scopes=['https://www.googleapis.com/auth/devstorage.read_only'],
    quota_project_id='your-gcp-project-id',
    cache_credentials=True,
    force_reauthentication=True  # This will clear the cache and prompt for a new login
)
```

---

### 2. For Headless Environments: `from_manual_flow`

Perfect for environments without a direct browser interface, such as remote SSH sessions, Docker containers, or Google Colab.

```python
from simple_gcp_auth import from_manual_flow
from google.cloud import bigquery

# This will print a URL. Open it, authenticate, and paste the authorization code back.
credentials = from_manual_flow(
    scopes=['https://www.googleapis.com/auth/bigquery.readonly'],
    quota_project_id='your-gcp-project-id'
)

# Use the credentials with a GCP client
bq_client = bigquery.Client(credentials=credentials, project='your-gcp-project-id')
query = "SELECT corpus FROM `bigquery-public-data.samples.shakespeare` LIMIT 10"
for row in bq_client.query(query):
    print(row.corpus)
```

---

### 3. For GCP Environments: `from_application_default_credentials`

The standard way to authenticate when your code is running within GCP (e.g., Compute Engine, GKE, Cloud Run, App Engine). It automatically finds credentials from the environment.

```python
from simple_gcp_auth import from_application_default_credentials
from google.cloud import pubsub_v1

# ADC will be found automatically from the environment.
credentials = from_application_default_credentials(
    scopes=['https://www.googleapis.com/auth/pubsub'],
    quota_project_id='your-gcp-project-id'
)

# Use the credentials with a GCP client
publisher = pubsub_v1.PublisherClient(credentials=credentials)
# ... use the client
```

---

### 4. For Service Account Impersonation (using ADC): `from_adc_impersonated`

Use this when your code, running with some base credentials (ADC), needs to assume the identity of another service account or user. The principal running the code must have the "Service Account Token Creator" role.

```python
from simple_gcp_auth import from_adc_impersonated

target_sa = 'my-target-service-account@your-gcp-project-id.iam.gserviceaccount.com'

# Get credentials for the target service account
impersonated_credentials = from_adc_impersonated(
    username=target_sa,
    scopes=['https://www.googleapis.com/auth/cloud-platform']
)

# Now you can use impersonated_credentials to act as the target service account
```

---

### 5. For Domain-Wide Delegation (Interactive): `from_interactive_user_delegated`

A more advanced flow for when a user needs to interactively authenticate to then impersonate a service account or another user that has been granted domain-wide delegation.

**Prerequisites:**
- The service account must be configured for Domain-Wide Delegation in the Google Workspace Admin console.
- The authenticating user must have the "Service Account Token Creator" role on the service account.

```python
from simple_gcp_auth import from_interactive_user_delegated

delegated_credentials = from_interactive_user_delegated(
    service_account_email='dwd-service-account@your-project.iam.gserviceaccount.com',
    subject_email='user-to-impersonate@your-domain.com',
    scopes=['https://www.googleapis.com/auth/admin.directory.user.readonly'],
    quota_project_id='your-gcp-project-id',
    cache_credentials=True,  # Caching is also supported here
    force_reauthentication=True # This will clear the underlying user token
)

# Use these credentials to call APIs on behalf of the subject_email
```

---

### 6. For Domain-Wide Delegation (Manual): `from_manual_flow_delegated`

Similar to the interactive delegation, but for headless environments. It uses the manual flow to get the initial user credentials.

**Prerequisites:**
- The service account must be configured for Domain-Wide Delegation in the Google Workspace Admin console.
- The authenticating user must have the "Service Account Token Creator" role on the service account.

```python
from simple_gcp_auth import from_manual_flow_delegated

delegated_credentials = from_manual_flow_delegated(
    service_account_email='dwd-service-account@your-project.iam.gserviceaccount.com',
    subject_email='user-to-impersonate@your-domain.com',
    scopes=['https://www.googleapis.com/auth/admin.directory.user.readonly'],
    quota_project_id='your-gcp-project-id',
    cache_credentials=True,  # Caching is also supported here
    force_reauthentication=True # This will clear the underlying user token
)

# Use these credentials to call APIs on behalf of the subject_email
```

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue on the [GitHub repository](https://github.com/shuvalov/simple-gcp-auth).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.