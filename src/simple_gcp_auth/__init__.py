"""
Provides simplified credential fetching for Google Cloud Platform.

This module contains helper functions to abstract the complexities of acquiring
different types of Google credentials, including interactive user auth,
Application Default Credentials (ADC), and impersonated credentials.
"""
from typing import List, Optional
import os
import hashlib
import base64
import json
import keyring
import requests
import logging
import socket
from urllib.parse import urlencode

import google.auth
import google.auth.iam
import google.auth.impersonated_credentials
import google.auth.transport.requests
from google.auth.exceptions import DefaultCredentialsError
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

# logger
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())
# Well know client ID of gcloud application.
CLIENT_ID = "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com"
CLIENT_SECRET = "d-FL95Q19q7MQmFpd7hHD0Ty"
_WELL_KNOWN_CLIENT_CONFIG = {
    "installed": {
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://accounts.google.com/o/oauth2/token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
}
# Scopes and URLs used for credentials impersonation
_IMPERSONATION_SCOPES = ["https://www.googleapis.com/auth/iam"]
_TOKEN_URL = "https://accounts.google.com/o/oauth2/token"
_KEYCHAIN_SERVICE_NAME = "pypi_simple_gcp_auth"
_MANIFEST_KEY = f"{_KEYCHAIN_SERVICE_NAME}_manifest"


def _get_cache_key(**kwargs) -> str:
    """
    Generates a deterministic cache key from function arguments.
    """
    # Per requirements, exclude subject_email and the cache flag itself.
    kwargs.pop("subject_email", None)
    kwargs.pop("cache_credentials", None)
    kwargs.pop("force_reauthentication", None)

    # Sort by key to ensure order-insensitivity.
    sorted_items = sorted(kwargs.items())

    # Create a stable string representation using JSON.
    encoded_str = json.dumps(sorted_items, sort_keys=True)

    # Return the SHA-256 hash of the string.
    return hashlib.sha256(encoded_str.encode("utf-8")).hexdigest()


def _get_token_manifest() -> dict:
    """Retrieves the token manifest from the keychain."""
    manifest_str = keyring.get_password(_KEYCHAIN_SERVICE_NAME, _MANIFEST_KEY)
    if manifest_str:
        try:
            return json.loads(manifest_str)
        except json.JSONDecodeError:
            logger.warning("Could not decode token manifest. Starting fresh.")
            return {}
    return {}


def _set_token_manifest(manifest: dict):
    """Saves the token manifest to the keychain."""
    keyring.set_password(
        _KEYCHAIN_SERVICE_NAME, _MANIFEST_KEY, json.dumps(manifest)
    )


def _clear_cached_token(**kwargs):
    """
    Clears a cached token from the keychain and manifest.
    """
    cache_key = _get_cache_key(**kwargs)
    manifest = _get_token_manifest()

    if cache_key in manifest:
        logger.debug(f"Force re-authentication: clearing token with key {cache_key[:8]}...")
        # Remove from keychain
        keyring.delete_password(_KEYCHAIN_SERVICE_NAME, cache_key)
        # Remove from manifest
        del manifest[cache_key]
        _set_token_manifest(manifest)


def _find_compatible_token_in_cache(
    required_scopes: List[str],
    quota_project_id: Optional[str] = None
) -> Optional[Credentials]:
    """
    Finds a cached token that has at least the required scopes.
    """
    manifest = _get_token_manifest()
    required_scopes_set = set(required_scopes)

    for cache_key, token_info in manifest.items():
        # 1. Check if quota_project_id matches
        if token_info.get("quota_project_id") != quota_project_id:
            continue

        # 2. Check if cached scopes are a superset of required scopes
        cached_scopes_set = set(token_info.get("scopes", []))
        if not cached_scopes_set.issuperset(required_scopes_set):
            continue

        # 3. If compatible, try to create credentials from it
        refresh_token = keyring.get_password(_KEYCHAIN_SERVICE_NAME, cache_key)
        if refresh_token:
            try:
                logger.debug(f"Found compatible cached token with key: {cache_key[:8]}...")
                # Use the original scopes the token was created with
                return _create_creds_from_refresh_token(
                    refresh_token, token_info["scopes"], quota_project_id
                )
            except Exception as e:
                logger.debug(f"Cached token {cache_key[:8]} is invalid, removing. Error: {e}")
                # If token is invalid, remove it from keychain and manifest
                keyring.delete_password(_KEYCHAIN_SERVICE_NAME, cache_key)
                del manifest[cache_key]
                _set_token_manifest(manifest)
        else:
            # If token is in manifest but not in keychain, clean up manifest
            logger.warning(f"Token for key {cache_key[:8]} found in manifest but not in keychain. Cleaning up.")
            del manifest[cache_key]
            _set_token_manifest(manifest)

    return None


def _create_creds_from_refresh_token(
    refresh_token: str,
    scopes: List[str],
    quota_project_id: Optional[str] = None
) -> Credentials:
    """Creates a Credentials object from a refresh token."""
    creds = Credentials(
        token=None,  # No access token yet, will be fetched on first use.
        refresh_token=refresh_token,
        token_uri=_WELL_KNOWN_CLIENT_CONFIG["installed"]["token_uri"],
        client_id=_WELL_KNOWN_CLIENT_CONFIG["installed"]["client_id"],
        client_secret=_WELL_KNOWN_CLIENT_CONFIG["installed"]["client_secret"],
        scopes=scopes,
    )
    if quota_project_id:
        creds = creds.with_quota_project(quota_project_id)

    # Refresh the credentials to get a valid access token immediately.
    request = google.auth.transport.requests.Request()
    creds.refresh(request)
    return creds


def _find_free_port():
    """Finds and returns an available TCP port on the system."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]


def from_interactive_user(
    scopes: List[str] = ['openid'],
    quota_project_id: Optional[str] = None,
    cache_credentials: bool = False,
    force_reauthentication: bool = False
) -> Credentials:
    """Creates user credentials via an interactive local server flow.

    This is useful for local development and command-line tools. It will
    open a browser window for the user to authenticate.

    Args:
        scopes: A list of OAuth 2.0 scopes to request.
        quota_project_id: The project ID to use for quota and billing.
        cache_credentials: If True, securely caches the refresh token in the
            system keychain to avoid repeated authentication prompts. Defaults
            to False.
        force_reauthentication: If True, clears any cached credentials for this
            configuration and forces a new authentication flow. Defaults to False.

    Returns:
        An authorized `google.oauth2.credentials.Credentials` object.

    Raises:
        Exception: If the authentication flow fails.
    """
    if cache_credentials and force_reauthentication:
        _clear_cached_token(scopes=scopes, quota_project_id=quota_project_id)

    if cache_credentials:
        cached_creds = _find_compatible_token_in_cache(scopes, quota_project_id)
        if cached_creds:
            return cached_creds

    # If cache is not used, or if it is empty/invalid, proceed with interactive flow.
    try:
        flow = InstalledAppFlow.from_client_config(_WELL_KNOWN_CLIENT_CONFIG, scopes)
        port = _find_free_port()
        credentials = flow.run_local_server(port=port)

        if cache_credentials and credentials.refresh_token:
            cache_key = _get_cache_key(scopes=scopes, quota_project_id=quota_project_id)
            logger.debug(f"Saving new refresh token to keychain with key: {cache_key[:8]}...")
            keyring.set_password(
                _KEYCHAIN_SERVICE_NAME, cache_key, credentials.refresh_token
            )
            # Update the manifest
            manifest = _get_token_manifest()
            manifest[cache_key] = {
                "scopes": scopes,
                "quota_project_id": quota_project_id,
            }
            _set_token_manifest(manifest)

        if quota_project_id:
            return credentials.with_quota_project(quota_project_id)
        return credentials
    except Exception as e:
        print(f"Failed to complete interactive authentication flow: {e}")
        raise


def from_application_default_credentials(
    scopes: List[str],
    quota_project_id: Optional[str] = None
) -> Credentials:
    """Loads credentials from Application Default Credentials (ADC).

    ADC is the standard way to get credentials in a GCP environment.
    It checks for credentials in the following order:
    1. GOOGLE_APPLICATION_CREDENTIALS environment variable.
    2. gcloud CLI default credentials.
    3. Attached service account (on GCE, GKE, Cloud Run, etc.).

    Args:
        scopes: A list of OAuth 2.0 scopes to request.
        quota_project_id: The project ID to use for quota and billing.

    Returns:
        An authorized `google.oauth2.credentials.Credentials` object.

    Raises:
        google.auth.exceptions.DefaultCredentialsError: If ADC are not found.
    """
    try:
        credentials, project = google.auth.default(
            scopes=scopes, quota_project_id=quota_project_id
        )
        return credentials
    except DefaultCredentialsError:
        print(
            "Error: Application Default Credentials not found. Please run "
            "'gcloud auth application-default login' or set the "
            "GOOGLE_APPLICATION_CREDENTIALS environment variable."
        )
        raise


def from_adc_impersonated(
    username: str,
    scopes: List[str]
) -> Credentials:
    """
    Creates impersonated credentials for a target service account user.

    This uses the Application Default Credentials of the environment to
    impersonate another service account, provided the principal has the
    "Service Account Token Creator" IAM role.

    Args:
        username: The email address of the service account to impersonate.
        scopes: A list of OAuth 2.0 scopes to request for the impersonated credentials.

    Returns:
        An impersonated `google.oauth2.credentials.Credentials` object.

    Raises:
        google.auth.exceptions.DefaultCredentialsError: If base ADC are not found.
    """
    try:
        # Load the base credentials from the environment (ADC)
        credentials, _ = google.auth.default()

        # If the base credentials are user credentials, they might support
        # impersonation directly.
        if hasattr(credentials, "with_subject"):
            return credentials.with_subject(username).with_scopes(scopes)

        # Otherwise, assume they are service account credentials and use the
        # IAM API to generate a token for the target user.
        request = google.auth.transport.requests.Request()
        scoped_credentials = credentials.with_scopes(_IMPERSONATION_SCOPES)
        scoped_credentials.refresh(request)

        signer = google.auth.iam.Signer(
            request, scoped_credentials, scoped_credentials.service_account_email
        )
        return service_account.Credentials(
            signer=signer,
            service_account_email=scoped_credentials.service_account_email,
            token_uri=_TOKEN_URL,
            scopes=scopes,
            subject=username,
        )
    except DefaultCredentialsError:
        print(
            "Error: Application Default Credentials not found. The principal "
            "running this code needs credentials to impersonate another account."
        )
        raise


def from_manual_flow(
        scopes: List[str] = ['openid'],
        quota_project_id: Optional[str] = None,
        cache_credentials: bool = False,
        force_reauthentication: bool = False
) -> Credentials:
    """
    Performs the manual Authorization Code Flow with the required PKCE security.
    The only method to i found to get Google SDK API token inside of Google Colab.
    """
    if cache_credentials and force_reauthentication:
        _clear_cached_token(scopes=scopes, quota_project_id=quota_project_id)

    if cache_credentials:
        cached_creds = _find_compatible_token_in_cache(scopes, quota_project_id)
        if cached_creds:
            return cached_creds

    REDIRECT_URI = "https://sdk.cloud.google.com/applicationdefaultauthcode.html"

    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('utf-8')
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).rstrip(b'=').decode('utf-8')

    # 2. Build the authorization URL.
    auth_base_url = "https://accounts.google.com/o/oauth2/v2/auth"
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(scopes),
        "access_type": "offline",
        "prompt": "consent",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    auth_url = f"{auth_base_url}?{urlencode(params)}"

    # 3. Prompt the user to authorize and provide the code.
    print('--- MANUAL AUTHENTICATION REQUIRED ---')
    print('1. Go to this URL in your browser:')
    print(auth_url)
    print('\n2. After you grant permissions, you will be redirected to a page showing a "Success!" message.')
    print('3. In the address bar of that SUCCESS page, there will be a long "code" parameter.')
    
    code = input('\n4. Copy ONLY the value of the code and paste it here: ').strip()

    # 4. Exchange the code for a token.
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "code_verifier": code_verifier,
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
    }
    response = requests.post(token_url, data=token_data)
    response.raise_for_status()

    # 5. Create the credentials object from the server's response.
    token_info = response.json()
    
    # We must explicitly pass the quota_project_id when creating the credentials.
    creds = Credentials(
        token=token_info['access_token'],
        refresh_token=token_info.get('refresh_token'),
        token_uri=token_url,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        scopes=scopes,
        quota_project_id=quota_project_id
    )
    if cache_credentials and creds.refresh_token:
        cache_key = _get_cache_key(scopes=scopes, quota_project_id=quota_project_id)
        logger.debug(f"Saving new refresh token to keychain with key: {cache_key[:8]}...")
        keyring.set_password(
            _KEYCHAIN_SERVICE_NAME, cache_key, creds.refresh_token
        )
        # Update the manifest
        manifest = _get_token_manifest()
        manifest[cache_key] = {
            "scopes": scopes,
            "quota_project_id": quota_project_id,
        }
        _set_token_manifest(manifest)
    return creds


def from_interactive_user_delegated(
    service_account_email: str,
    subject_email: str,
    scopes: List[str],
    quota_project_id: str,
    cache_credentials: bool = False,
    force_reauthentication: bool = False,
) -> Credentials:
    """
    Creates delegated credentials via an interactive user flow to impersonate a service account.

    This function is for a user running the script locally who does not have
    gcloud or ADC configured. It initiates an interactive browser-based
    authentication flow to get the user's credentials. These credentials are then
    used to impersonate a service account that has Domain-Wide Delegation (DWD)
    authority.

    Prerequisites:
    1. The user authenticating via the browser has the "Service Account Token Creator"
       (`roles/iam.serviceAccountTokenCreator`) IAM role on the `service_account_email`.
    2. The service account has Domain-Wide Delegation configured in the Google
       Workspace Admin console for the requested `scopes`.

    Args:
        service_account_email: The email of the service account configured for DWD.
        subject_email: The email address of the Google Workspace user to impersonate.
        scopes: A list of OAuth 2.0 scopes for the final delegated credentials.
        quota_project_id: The project ID to use for quota and billing.
        cache_credentials: If True, the underlying interactive user authentication
            will use the system keychain to cache the user's refresh token.
            Defaults to False.
        force_reauthentication: If True, clears any cached credentials for this
            configuration and forces a new authentication flow. Defaults to False.

    Returns:
        A `google.oauth2.credentials.Credentials` object with delegated authority.
    """
    try:
        # 1. Get user credentials via interactive flow.
        # The user needs cloud-platform scope to be able to impersonate.
        logger.debug("Starting interactive user authentication to get base credentials...")
        user_credentials = from_interactive_user(
            scopes=_IMPERSONATION_SCOPES,
            quota_project_id=quota_project_id,
            cache_credentials=cache_credentials,
            force_reauthentication=force_reauthentication,
        )
        logger.debug("Interactive authentication successful.")
        # 2. Use the user's credentials to impersonate the service account.
        logger.debug(f"Impersonating service account: {service_account_email}...")
        service_account_creds = google.auth.impersonated_credentials.Credentials(
            source_credentials=user_credentials,
            target_principal=service_account_email,
            target_scopes=scopes,
            lifetime=3600,
            subject=subject_email
        )
        auth_request = google.auth.transport.requests.Request()
        service_account_creds.refresh(auth_request)
        logger.debug("Successfully created delegated credentials.")
        return service_account_creds

    except Exception as e:
        print(f"An error occurred during the interactive domain-wide delegation flow: {e}")
        raise


def from_manual_flow_delegated(
    service_account_email: str,
    subject_email: str,
    scopes: List[str],
    quota_project_id: str,
    cache_credentials: bool = False,
    force_reauthentication: bool = False,
) -> Credentials:
    """
    Creates delegated credentials via a manual user flow to impersonate a service account.

    This function is for a user running the script in a headless environment
    (like Google Colab) who does not have gcloud or ADC configured. It
    initiates a manual authentication flow to get the user's credentials.
    These credentials are then used to impersonate a service account that has
    Domain-Wide Delegation (DWD) authority.

    Prerequisites:
    1. The user authenticating via the manual flow has the "Service Account Token Creator"
       (`roles/iam.serviceAccountTokenCreator`) IAM role on the `service_account_email`.
    2. The service account has Domain-Wide Delegation configured in the Google
       Workspace Admin console for the requested `scopes`.

    Args:
        service_account_email: The email of the service account configured for DWD.
        subject_email: The email address of the Google Workspace user to impersonate.
        scopes: A list of OAuth 2.0 scopes for the final delegated credentials.
        quota_project_id: The project ID to use for quota and billing.
        cache_credentials: If True, the underlying manual user authentication
            will use the system keychain to cache the user's refresh token.
            Defaults to False.
        force_reauthentication: If True, clears any cached credentials for this
            configuration and forces a new authentication flow. Defaults to False.

    Returns:
        A `google.oauth2.credentials.Credentials` object with delegated authority.
    """
    try:
        # 1. Get user credentials via manual flow.
        # The user needs cloud-platform scope to be able to impersonate.
        logger.debug("Starting manual user authentication to get base credentials...")
        user_credentials = from_manual_flow(
            scopes=_IMPERSONATION_SCOPES,
            quota_project_id=quota_project_id,
            cache_credentials=cache_credentials,
            force_reauthentication=force_reauthentication,
        )
        logger.debug("Manual authentication successful.")
        # 2. Use the user's credentials to impersonate the service account.
        logger.debug(f"Impersonating service account: {service_account_email}...")
        service_account_creds = google.auth.impersonated_credentials.Credentials(
            source_credentials=user_credentials,
            target_principal=service_account_email,
            target_scopes=scopes,
            lifetime=3600,
            subject=subject_email
        )
        auth_request = google.auth.transport.requests.Request()
        service_account_creds.refresh(auth_request)
        logger.debug("Successfully created delegated credentials.")
        return service_account_creds

    except Exception as e:
        print(f"An error occurred during the manual domain-wide delegation flow: {e}")
        raise