# pylint: disable=abstract-method,attribute-defined-outside-init
"""
JupyterHub service for fetching and refreshing access tokens.
"""

import dataclasses
import os
import pathlib
import secrets
import time
from typing import Any, Dict, List, Literal, Optional

import oauthlib.oauth2  # type: ignore[import]
import oauthlib.oauth2.rfc6749.errors  # type: ignore[import]
import requests
import requests_oauthlib  # type: ignore[import]
from baydemir import parsing
from jupyterhub.services import auth  # type: ignore[import]
from tornado import ioloop, template, web

from scitokens.jupyter import token_db

THIS_FILE = pathlib.Path(__file__)
THIS_DIR = THIS_FILE.parent
TEMPLATES = template.Loader(os.fspath(THIS_DIR / "templates"))

CONFIG_FILE = pathlib.Path("/etc/scitokens/jupyterhub_service.yaml")
JUPYTERHUB_BASE_URL = os.environ["JUPYTERHUB_BASE_URL"]
SERVICE_NAME = os.environ.get("SCITOKENS_SERVICE_NAME", "scitokens")
SERVICE_PORT = int(os.environ["SCITOKENS_SERVICE_PORT"])
SERVICE_BASE_URL = os.environ["JUPYTERHUB_SERVICE_PREFIX"]


# Instruct `oauthlib` to ignore differences between the requested and
# granted access token scopes.

os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"  # nosec


# As long as everything runs in a single thread, we can use any mutable
# object as a cache that persists between requests but is lost whenever the
# service is restarted.

csrf_cache: Dict[str, Any] = {}

device_code_cache: Dict[str, Any] = {}

token_cache: token_db.OAuth2TokenDB = token_db.InMemoryOAuth2TokenDB()


@dataclasses.dataclass
class OAuth2IssuerConfig:
    ## User-facing name for this issuer.
    name: str

    ## Short identifier for this issuer to use in URLs and the like.
    id: str

    ## Standard OAuth2 configuration values.
    auth_url: str
    token_url: str
    scope: str

    ## URL for is this issuer uses the device flow.
    device_auth_url: Optional[str] = None

    ## Path to the public TLS certificate/key for this issuer.
    tls_cert: Optional[str] = None


@dataclasses.dataclass
class SecretOAuth2IssuerConfig(OAuth2IssuerConfig):
    ## Standard OAuth2 configuration values.
    client_id: str = ""
    client_secret: str = ""


@dataclasses.dataclass
class ServiceConfig:
    """
    Defines the format of this service's configuration sans secrets.
    """

    oauth2: List[OAuth2IssuerConfig] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class SecretServiceConfig:
    """
    Defines the format of this service's configuration.
    """

    oauth2: List[SecretOAuth2IssuerConfig] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class APIResponse:
    """
    Defines the format of this service's API responses.
    """

    status: Literal["ok", "error"]
    data: Dict[str, Any]

    def asdict(self):
        """
        Unparses this data class instance into a dictionary.
        """

        return parsing.unparse(self)


class IndexHandler(auth.HubOAuthenticated, web.RequestHandler):
    """
    Returns a page where the current user can manage their tokens.
    """

    def initialize(self, config: SecretServiceConfig):
        self._config = config

    @web.authenticated
    def get(self):
        html = TEMPLATES.load("index.html")

        self.finish(
            html.generate(
                oauth2_config=self._config.oauth2,
                jupyterhub_base_url=JUPYTERHUB_BASE_URL,
                service_base_url=SERVICE_BASE_URL,
            )
        )


class ConfigHandler(web.RequestHandler):
    """
    Returns the service's configuration sans secrets.
    """

    def initialize(self, config: SecretServiceConfig):
        self._config = config

    def get(self):
        oauth2 = [parsing.reparse(issuer, OAuth2IssuerConfig) for issuer in self._config.oauth2]

        config = ServiceConfig(oauth2)
        resp = APIResponse("ok", {"config": config})

        self.finish(resp.asdict())


class OAuth2IssuerHandler(auth.HubOAuthenticated, web.RequestHandler):
    """
    Manages tokens from the configured OAuth2-based issuer.

    This handler understands the following requests (API routes):

      - GET {service_base_url}tokens/{config.id}:

        Returns an access token.

      - GET {service_base_url}tokens/{config.id}/auth:

        Starts the authorization flow.

        Also functions as the authorization callback.
    """

    def initialize(self, config: SecretOAuth2IssuerConfig):
        self._config = config

    @web.authenticated
    def get(self, is_auth):
        ## FIXME: Do not hard-code the service's name.

        self._request_url = f"https://{self.request.host}{self.request.uri}"
        self._callback_url = f"https://{self.request.host}{self.request.path}"
        self._uid = self.get_current_user()["name"]

        if is_auth == "/auth":
            if self.get_argument("code", default=None):
                self._process_auth_callback()
            else:
                self._process_auth_request()
        elif is_auth == "/device_auth":
            self._process_device_auth_request()
        else:
            self._process_fetch_request()

    def _finish_with_error(self, status: int, message: str) -> None:
        resp = APIResponse("error", {"message": message})

        self.set_status(status)
        self.finish(resp.asdict())

    def _process_auth_request(self) -> None:
        session = requests_oauthlib.OAuth2Session(
            self._config.client_id,
            scope=self._config.scope,
            redirect_uri=self._callback_url,
        )

        auth_url, state = session.authorization_url(self._config.auth_url)

        csrf_cache[self._uid] = state

        self.redirect(auth_url)

    def _process_auth_callback(self) -> None:
        state = self.get_argument("state")

        if state == csrf_cache[self._uid]:

            session = requests_oauthlib.OAuth2Session(
                self._config.client_id,
                scope=self._config.scope,
                redirect_uri=self._callback_url,
            )

            new_token = session.fetch_token(
                self._config.token_url,
                client_secret=self._config.client_secret,
                authorization_response=self._request_url,
            )

            self._put_token_into_cache(new_token)

            self.redirect(SERVICE_BASE_URL)

        else:
            self._finish_with_error(400, "Invalid state")

    def _process_device_auth_request(self) -> None:
        if self._config.device_auth_url:
            client = oauthlib.oauth2.DeviceClient(self._config.client_id)
            session = requests_oauthlib.OAuth2Session(
                self._config.client_id,
                client=client,
                scope=self._config.scope,
            )

            auth_url, state = session.authorization_url(self._config.device_auth_url)
            auth_data = requests.get(auth_url, verify=self._config.tls_cert).json()
            device_code_cache[self._uid] = auth_data["device_code"]

            html = TEMPLATES.load("device-auth.html")

            self.finish(
                html.generate(
                    url=auth_data["verification_uri"],
                    name=auth_data["verification_uri"],
                    code=auth_data["user_code"],
                )
            )
        else:
            self._finish_with_error(404, "Device authorization flow is not supported")

    def _process_fetch_request(self) -> None:
        if self._uid in device_code_cache:
            client = oauthlib.oauth2.DeviceClient(self._config.client_id)

            new_token = requests.post(
                self._config.token_url,
                data={
                    "client_id": self._config.client_id,
                    "scope": self._config.scope,
                    "device_code": device_code_cache[self._uid],
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                },
            ).json()

            del device_code_cache[self._uid]

            resp = APIResponse("ok", {"raw_token": new_token})

        elif token := self._get_token_from_cache():
            if token.expires_in and (token.updated_at + token.expires_in - time.time()) <= 30:
                if token := self._process_refresh_request(token):
                    resp = APIResponse("ok", {"token": token})
                else:
                    resp = APIResponse("error", {"message": "Failed to refresh token"})
            else:
                resp = APIResponse("ok", {"token": token})
        else:
            resp = APIResponse("error", {"message": "No token available"})

        self.finish(resp.asdict())

    def _process_refresh_request(
        self, token: token_db.OAuth2Token
    ) -> Optional[token_db.OAuth2Token]:
        session = requests_oauthlib.OAuth2Session(self._config.client_id, token=token)

        try:
            new_token = session.refresh_token(
                self._config.token_url,
                client_id=self._config.client_id,
                client_secret=self._config.client_secret,
            )
        except oauthlib.oauth2.rfc6749.errors.InvalidGrantError:
            return None
        else:
            self._put_token_into_cache(new_token)

            return self._get_token_from_cache()

    def _put_token_into_cache(self, token) -> None:
        if expires_in := token.get("expires_in"):
            expires_in = int(expires_in)

        token_cache.put(
            self._config.id + ":" + self._uid,
            access_token=token["access_token"],
            token_type=token["token_type"],
            expires_in=expires_in,
            refresh_token=token.get("refresh_token"),
            scope=token.get("scope"),
        )

    def _get_token_from_cache(self) -> Optional[token_db.OAuth2Token]:
        return token_cache.get(self._config.id + ":" + self._uid)


def main() -> None:
    """
    Runs this service as a standalone web server.
    """

    config = parsing.load_yaml(CONFIG_FILE, SecretServiceConfig)

    handlers: List[Any] = [
        (SERVICE_BASE_URL, IndexHandler, {"config": config}),
        (SERVICE_BASE_URL + "oauth_callback", auth.HubOAuthCallbackHandler),
        (SERVICE_BASE_URL + "config", ConfigHandler, {"config": config}),
    ]

    for issuer in config.oauth2:
        handlers.append(
            (
                SERVICE_BASE_URL + f"tokens/{issuer.id}(/auth|/device_auth)?",
                OAuth2IssuerHandler,
                {"config": issuer},
            )
        )

    app = web.Application(handlers, cookie_secret=secrets.token_urlsafe(64))

    app.listen(SERVICE_PORT)

    ioloop.IOLoop.current().start()


if __name__ == "__main__":
    main()
