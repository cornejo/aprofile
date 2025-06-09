#! /usr/bin/env python3

import base64
import binascii
import datetime
import hashlib
import inspect
import json
import os
import pickle
import requests
import sirp  # type: ignore
import subprocess
import sys
import traceback

from classes import Config_2fa, Config_Profile
from dataclasses import dataclass
from enum import Enum
from requests.adapters import HTTPAdapter
from requests.models import Response, PreparedRequest
from tabulate import tabulate
from typing import Any
from urllib3.util import Retry  # type: ignore


try:
    from config import config
except ImportError:
    print("Config file not found. Please create a config.py file with your settings.")
    sys.exit(1)

# Set this to true to log all requests and responses to a file
# Useful for debugging
RAW_LOGGING = False


@dataclass
class Attributes:
    name: str
    profileType: str
    templateName: str | None
    isOfflineProfile: bool
    teamId: str


class ProfileType(Enum):
    IOS_APP_DEVELOPMENT = "IOS_APP_DEVELOPMENT"
    IOS_APP_STORE = "IOS_APP_STORE"
    IOS_APP_ADHOC = "IOS_APP_ADHOC"
    IOS_APP_INHOUSE = "IOS_APP_INHOUSE"
    MAC_APP_DEVELOPMENT = "MAC_APP_DEVELOPMENT"
    MAC_APP_STORE = "MAC_APP_STORE"
    MAC_APP_DIRECT = "MAC_APP_DIRECT"
    TVOS_APP_DEVELOPMENT = "TVOS_APP_DEVELOPMENT"
    TVOS_APP_STORE = "TVOS_APP_STORE"
    TVOS_APP_ADHOC = "TVOS_APP_ADHOC"
    TVOS_APP_INHOUSE = "TVOS_APP_INHOUSE"
    MAC_CATALYST_APP_DEVELOPMENT = "MAC_CATALYST_APP_DEVELOPMENT"
    MAC_CATALYST_APP_STORE = "MAC_CATALYST_APP_STORE"
    MAC_CATALYST_APP_DIRECT = "MAC_CATALYST_APP_DIRECT"

    # As of 2022-06-25, only available with Apple ID auth
    MAC_APP_INHOUSE = "MAC_APP_INHOUSE"
    MAC_CATALYST_APP_INHOUSE = "MAC_CATALYST_APP_INHOUSE"


def pretty_type(profile_type: str) -> str:
    if profile_type in [
        ProfileType.IOS_APP_DEVELOPMENT.value,
        ProfileType.MAC_APP_DEVELOPMENT.value,
        ProfileType.TVOS_APP_DEVELOPMENT.value,
        ProfileType.MAC_CATALYST_APP_DEVELOPMENT.value,
    ]:
        return "Development"
    if profile_type in [
        ProfileType.IOS_APP_STORE.value,
        ProfileType.MAC_APP_STORE.value,
        ProfileType.TVOS_APP_STORE.value,
        ProfileType.MAC_CATALYST_APP_STORE.value,
    ]:
        return "AppStore"
    if profile_type in [ProfileType.IOS_APP_ADHOC.value, ProfileType.TVOS_APP_ADHOC.value]:
        return "AdHoc"
    if profile_type in [
        ProfileType.IOS_APP_INHOUSE.value,
        ProfileType.TVOS_APP_INHOUSE.value,
        ProfileType.MAC_APP_INHOUSE.value,
        ProfileType.MAC_CATALYST_APP_INHOUSE.value,
    ]:
        return "InHouse"
    if profile_type in [ProfileType.MAC_APP_DIRECT.value, ProfileType.MAC_CATALYST_APP_DIRECT.value]:
        return "Direct"

    raise Exception(f"Unknown profile type: {profile_type}")


class CSRFSession(requests.Session):
    """
    A session that automatically handles CSRF tokens.
    """

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.csrf = None
        self.csrf_ts = None
        self.logfile = None

    def request(self, method: str | bytes, url: str | bytes, *args: Any, **kwargs: Any):
        if self.csrf:
            headers = kwargs.setdefault("headers", {})
            headers["csrf"] = self.csrf
        if self.csrf_ts:
            headers = kwargs.setdefault("headers", {})
            headers["csrf_ts"] = self.csrf_ts

        response = super().request(method, url, *args, **kwargs)

        if "csrf" in response.headers:
            self.csrf = response.headers["csrf"]
            self.csrf_ts = response.headers.get("csrf_ts", None)
            self.headers["csrf"] = self.csrf
            if self.csrf_ts:
                self.headers["csrf_ts"] = self.csrf_ts

        return response

    def send(self, request: PreparedRequest, **kwargs: Any) -> Response:
        if RAW_LOGGING:
            if not self.logfile:
                self.logfile = open("raw_requests.log", "w")

            print("=== REQUEST ===", file=self.logfile)
            print(f"{request.method} {request.url}", file=self.logfile)
            for k, v in request.headers.items():
                print(f"{k}: {v}", file=self.logfile)
            if request.body:
                print("\nBody:", file=self.logfile)
                print(request.body, file=self.logfile)

        response = super().send(request, **kwargs)

        if RAW_LOGGING:
            print("\n=== RESPONSE ===", file=self.logfile)
            print(f"Status: {response.status_code}", file=self.logfile)
            for k, v in response.headers.items():
                print(f"{k}: {v}", file=self.logfile)
            print("\nBody:", file=self.logfile)
            # limit to first 1000 chars
            print(response.text[:1000], file=self.logfile)
            print("=" * 40, file=self.logfile)

        return response


class Client:
    """
        client for connect to appstoreconnect.apple.com
        based on https://github.com/kinglon/buyer
        whick is based on
        based on https://github.com/fastlane/fastlane/blob/master/spaceship/
        usage:
    ```
    import appstoreconnect
    client = appstoreconnect.Client()
    responses = client.appAnalytics(appleId)
    for response in responses:
        print(response)
    ```
    """

    def debug(self, message: str):
        if self.logLevel and self.logLevel[0].lower() == "d":
            print(f"DEBUG: {message}")

    def error(self, message: str):
        print(f"ERROR: {message}")

    def __init__(
        self,
        cacheDirPath: str = "./cache",
        requestsRetry: bool = True,
        requestsRetrySettings: dict[str, Any] = {
            "total": 4,  # maximum number of retries
            "backoff_factor": 30,  # {backoff factor} * (2 ** ({number of previous retries}))
            "status_forcelist": [429, 500, 502, 503, 504],  # HTTP status codes to retry on
            "allowed_methods": ["HEAD", "TRACE", "GET", "PUT", "OPTIONS", "POST"],
        },
        logLevel: str | None = None,
        userAgent: str | None = None,
        legacySignin: bool = False,
    ):
        self.cacheDirPath = cacheDirPath
        self.requestsRetry = requestsRetry
        self.requestsRetrySettings = requestsRetrySettings
        self.logLevel = logLevel
        self.legacySignin = legacySignin

        try:
            os.makedirs(self.cacheDirPath, exist_ok=True)
        except OSError:
            if not os.path.isdir(self.cacheDirPath):
                raise

        self.xWidgetKey = self.getXWidgetKey()
        self.hashcash = self.getHashcash()
        self.headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/javascript",
            "X-Requested-With": "XMLHttpRequest",
            "X-Apple-Widget-Key": self.xWidgetKey,
            "X-Apple-HC": self.hashcash,
        }
        if userAgent:
            self.headers["User-Agent"] = userAgent

        # create a new session object
        self.session = CSRFSession()

        if self.requestsRetry:
            retryStrategy = Retry(**self.requestsRetrySettings)
            # create an http adapter with the retry strategy and mount it to session
            adapter = HTTPAdapter(max_retries=retryStrategy)
            self.session.mount("https://", adapter)

        self.session.headers.update(self.headers)
        self.authTypes = ["hsa2"]  # supported auth types
        self.xAppleIdSessionId: str | None = None
        self.scnt: str | None = None

        self.sessionCacheFile = self.cacheDirPath + "/sessionCacheFile.txt"
        self.getSession()

        self.apiSettingsAll = None

    def appleSessionHeaders(self):
        """
        return additional headers for appleconnect
        """

        defName = inspect.stack()[0][3]
        headers = {
            "X-Apple-Id-Session-Id": self.xAppleIdSessionId,
            "scnt": self.scnt,
        }
        self.debug(f"def={defName}: headers={headers}")

        return headers

    def getXWidgetKey(self) -> str:
        """
        generate x-widget-key
        https://github.com/fastlane/fastlane/blob/master/spaceship/lib/spaceship/client.rb#L599
        """

        defName = inspect.stack()[0][3]
        cacheFile = self.cacheDirPath + "/WidgetKey.txt"
        if os.path.exists(cacheFile) and os.path.getsize(cacheFile) > 0:
            with open(cacheFile, "r") as file:
                xWidgetKey = file.read()
        else:
            response = requests.get(
                "https://appstoreconnect.apple.com/olympus/v1/app/config",
                params={"hostname": "itunesconnect.apple.com"},
            )
            try:
                data = response.json()
            except Exception as e:
                self.error(f"def={defName}: failed get response.json(), error={str(e)}")
                raise
                # return None
            with open(cacheFile, "w") as file:
                file.write(data["authServiceKey"])
            xWidgetKey = data["authServiceKey"]

        self.debug(f"def={defName}: xWidgetKey={xWidgetKey}")
        return xWidgetKey

    def getHashcash(self):
        """
        generate hashcash
        https://github.com/fastlane/fastlane/blob/master/spaceship/lib/spaceship/hashcash.rb
        """

        defName = inspect.stack()[0][3]
        response = requests.get(f"https://idmsa.apple.com/appleauth/auth/signin?widgetKey={self.xWidgetKey}")
        headers = response.headers
        bits = headers["X-Apple-HC-Bits"]
        challenge = headers["X-Apple-HC-Challenge"]

        # make hc {{
        version = 1
        date = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        counter = 0
        bits = int(bits)
        while True:
            hc = f"{version}:{bits}:{date}:{challenge}::{counter}"
            sha1_hash = hashlib.sha1(hc.encode()).digest()
            binary_hash = bin(int.from_bytes(sha1_hash, byteorder="big"))[2:]  # сonvert to binary format
            if binary_hash.zfill(160)[:bits] == "0" * bits:  # checking leading bits
                self.debug(f"def={defName}: hc={hc}")
                return hc
            counter += 1
        # }}

    def handleTwoStepOrFactor(self, response: requests.Response, two_factor_authentication: Config_2fa):
        defName = inspect.stack()[0][3]

        responseHeaders = response.headers
        self.xAppleIdSessionId = responseHeaders["x-apple-id-session-id"]
        self.scnt = responseHeaders["scnt"]

        headers = self.appleSessionHeaders()

        r = self.session.get("https://idmsa.apple.com/appleauth/auth", headers=headers)
        self.debug(f"def={defName}: response.status_code={r.status_code}")
        if r.status_code in [200, 201]:
            # success
            try:
                data = r.json()
            except Exception as e:
                raise Exception(f"def={defName}: failed get response.json(), error={str(e)}")
            self.debug(f"def={defName}: response.json()={json.dumps(data)}")
            if "trustedDevices" in data or True:
                self.debug(f"def={defName}: trustedDevices forced")
                self.handleTwoStep(r, two_factor_authentication)
            elif "trustedPhoneNumbers" in data:
                # read code from phone
                self.debug(f"def={defName}: trustedPhoneNumbers={data['trustedPhoneNumbers']}")
                self.handleTwoFactor(r, two_factor_authentication)
            else:
                raise Exception(
                    f"Although response from Apple indicated activated Two-step Verification or Two-factor Authentication, we didn't know how to handle this response: #{r.text}"
                )

        else:
            raise Exception(f"def={defName}: bad response.status_code={r.status_code}")

        return

    def handleTwoStep(self, response: requests.Response, two_factor_authentication: Config_2fa):
        defName = inspect.stack()[0][3]

        # try:
        #    data = response.json()
        # except Exception as e:
        #    raise Exception(f"def={defName}: failed get response.json(), error={str(e)}")
        # securityCode = data["securityCode"]
        # "securityCode": {
        #     "length": 6,
        #     "tooManyCodesSent": false,
        #     "tooManyCodesValidated": false,
        #     "securityCodeLocked": false
        # },
        # codeLength = securityCode["length"]

        output = subprocess.check_output(two_factor_authentication.request_app)
        print(output)
        code = json.loads(output)["code"]

        payload: dict[str, dict[str, str] | str] = {
            "securityCode": {
                "code": str(code),
            },
        }
        headers = self.appleSessionHeaders()
        r = self.session.post(
            "https://idmsa.apple.com/appleauth/auth/verify/trusteddevice/securitycode", json=payload, headers=headers
        )
        self.debug(f"def={defName}: response.status_code={r.status_code}")
        # self.debug(f"def={defName}: response.json()={json.dumps(r.json())}")

        if r.status_code == 204:
            self.debug("Success!")
            self.storeSession()
            return True
        else:
            return False

    def handleTwoFactor(self, response: requests.Response, two_factor_authentication: Config_2fa):
        defName = inspect.stack()[0][3]

        try:
            data = response.json()
        except Exception as e:
            raise Exception(f"def={defName}: failed get response.json(), error={str(e)}")
        # securityCode = data["securityCode"]
        # "securityCode": {
        #     "length": 6,
        #     "tooManyCodesSent": false,
        #     "tooManyCodesValidated": false,
        #     "securityCodeLocked": false
        # },
        # codeLength = securityCode["length"]

        trustedPhone = data["trustedPhoneNumbers"][0]
        # phoneNumber = trustedPhone["numberWithDialCode"]
        phoneId: str = trustedPhone["id"]
        pushMode: str = trustedPhone["pushMode"]
        codeType = "phone"

        output = subprocess.check_output(two_factor_authentication.request_app)
        print(output)
        code = json.loads(output)["code"]

        payload: dict[str, dict[str, str] | str] = {
            "securityCode": {
                "code": str(code),
            },
            "phoneNumber": {
                "id": phoneId,
            },
            "mode": pushMode,
        }
        headers = self.appleSessionHeaders()
        r = self.session.post(
            f"https://idmsa.apple.com/appleauth/auth/verify/{codeType}/securitycode", json=payload, headers=headers
        )
        self.debug(f"def={defName}: response.status_code={r.status_code}")
        self.debug(f"def={defName}: response.json()={json.dumps(r.json())}")

        if r.status_code == 200:
            self.storeSession()
            return True
        else:
            return False

    def getSession(self):
        if os.path.exists(self.sessionCacheFile) and os.path.getsize(self.sessionCacheFile) > 0:
            from requests.cookies import RequestsCookieJar

            with open(self.sessionCacheFile, "rb") as f:
                cookies: RequestsCookieJar = pickle.load(f)
                self.session.cookies.update(cookies)  # type: ignore

    def storeSession(self):
        headers = self.appleSessionHeaders()
        _r = self.session.get("https://idmsa.apple.com/appleauth/auth/2sv/trust", headers=headers)
        with open(self.sessionCacheFile, "wb") as f:
            pickle.dump(self.session.cookies, f)

    def login(self, username: str, password: str, two_factor_authentication: Config_2fa) -> bool:
        defName = inspect.stack()[0][3]
        self.debug(f"def={defName}: starting")
        if self.legacySignin:
            return self._legacySignin(username, password, two_factor_authentication)
        else:
            return self._sirp(username, password, two_factor_authentication)

    def _sirp(self, username: str, password: str, two_factor_authentication: Config_2fa) -> bool:
        defName = inspect.stack()[0][3]

        client = sirp.Client(2048)
        a = client.start_authentication()

        # init request {{
        url = "https://idmsa.apple.com/appleauth/auth/signin/init"
        payload: dict[str, Any] = {
            "a": base64.b64encode(self.to_byte(a)).decode("utf-8"),
            "accountName": username,
            "protocols": ["s2k", "s2k_fo"],
        }
        response = self.session.post(url, json=payload, headers=self.headers)
        self.debug(f"def={defName}: url={url}, response.status_code={response.status_code}")
        try:
            data = response.json()
        except Exception as e:
            self.error(
                f"def={defName}: failed get response.json(), error={str(e)}, url='{url}', response.status_code='{str(response.status_code)}', response.text='{str(response.text)}'"
            )
            return False
        self.debug(
            f"def={defName}: Received SIRP signin init response, url='{url}', response.status_code={response.status_code}, data='{data}'"
        )

        if response.status_code != 200:
            message = f"url={url}, wrong response.status_code={response.status_code}, should be 200"
            self.error(f"def={defName}: {message}")
            raise Exception(message)
        # }}

        iteration = data["iteration"]
        salt = base64.b64decode(data["salt"])
        b = base64.b64decode(data["b"])
        c = data["c"]
        self.debug(f"def={defName}: salt='{salt}', b='{b}', c='{c}'")

        key_length = 32
        encrypted_password = self.pbkdf2(password, salt, iteration, key_length)
        self.debug(f"def={defName}: key_length='{key_length}', encrypted_password='{encrypted_password}'")

        m1 = client.process_challenge(
            username,
            self.to_hex(encrypted_password),
            self.to_hex(salt),
            self.to_hex(b),
            is_password_encrypted=True,
        )
        m2 = client.H_AMK

        if isinstance(m1, bool):
            raise Exception("Error processing SIRP challenge")

        if m2 is None:
            raise Exception("Error processing SIRP challenge, m2 is None")

        # complete request {{
        url = "https://idmsa.apple.com/appleauth/auth/signin/complete"
        payload = {
            "accountName": username,
            "c": c,
            "m1": base64.b64encode(self.to_byte(m1)).strip().decode("utf-8"),
            "m2": base64.b64encode(self.to_byte(m2)).strip().decode("utf-8"),
            "rememberMe": False,
        }
        response = self.session.post(url, json=payload, headers=self.headers, params={"isRememberMeEnabled": False})
        self.debug(f"def={defName}: url={url}, response.status_code={response.status_code}")
        try:
            data = response.json()
        except Exception as e:
            self.error(
                f"def={defName}: failed get response.json(), error={str(e)}, url='{url}', response.status_code='{str(response.status_code)}', response.text='{str(response.text)}'"
            )
            return False
        self.debug(
            f"def={defName}: Completed SIRP authentication, url='{url}', response.status_code={response.status_code}, data='{data}'"
        )

        if response.status_code == 409:
            # 2fa
            self.debug(f"def={defName}: response.status_code={response.status_code}, go to 2fa auth")
            self.handleTwoStepOrFactor(response, two_factor_authentication)
        elif response.status_code == 401:
            message = f"url={url}, response.status_code={response.status_code}, incorrect login or password"
            self.error(f"def={defName}: {message}")
            raise Exception(message)
        elif response.status_code != 200:
            message = f"url={url}, wrong response.status_code={response.status_code}, should be 200 or 409"
            self.error(f"def={defName}: {message}")
            raise Exception(message)
        # }}

        return True

    @staticmethod
    def pbkdf2(password: str, salt: bytes, iteration: int, key_length: int, digest: Any = hashlib.sha256):
        password_h = hashlib.sha256(password.encode()).digest()
        return hashlib.pbkdf2_hmac(digest().name, password_h, salt, iteration, key_length)

    @staticmethod
    def to_hex(s: bytes):
        return binascii.hexlify(s).decode()

    @staticmethod
    def to_byte(s: str):
        return binascii.unhexlify(s)

    def _legacySignin(self, username: str, password: str, two_factor_authentication: Config_2fa) -> bool:
        defName = inspect.stack()[0][3]

        url = "https://idmsa.apple.com/appleauth/auth/signin"
        headers = self.headers
        payload: dict[str, Any] = {"accountName": username, "password": password, "rememberMe": True}

        response = self.session.post(url, json=payload, headers=headers)
        self.debug(f"def={defName}: url={url}, response.status_code={response.status_code}")
        try:
            _data = response.json()
        except Exception as e:
            self.error(
                f"def={defName}: failed get response.json(), error={str(e)}, url='{url}', response.status_code='{str(response.status_code)}', response.text='{str(response.text)}'"
            )
            return False

        if response.status_code == 409:
            # 2fa
            self.debug(f"def={defName}: response.status_code={response.status_code}, go to 2fa auth")
            self.handleTwoStepOrFactor(response, two_factor_authentication)
        elif response.status_code == 401:
            message = f"url={url}, response.status_code={response.status_code}, incorrect login or password"
            self.error(f"def={defName}: {message}")
            raise Exception(message)
        elif response.status_code != 200:
            message = f"url={url}, wrong response.status_code={response.status_code}, should be 200 or 409"
            self.error(f"def={defName}: {message}")
            raise Exception(message)

        return True

    def getUserInfo(self):
        r = self.session.get("https://appstoreconnect.apple.com/olympus/v1/session")
        r.raise_for_status()
        data = r.json()

        return data

    def getTeamsInfo(self):
        p = self.session.prepare_request(
            requests.Request("POST", "https://developer.apple.com/services-account/QH65B2/account/listTeams.action")
        )
        p.headers.pop("Content-Type")
        r = self.session.send(p)
        r.raise_for_status()
        data = r.json()

        return data

    def getProfiles(self, teamId: str):
        headers = {
            "X-HTTP-Method-Override": "GET",
        }

        body: dict[str, Any] = {
            "urlEncodedQueryParams": "filter[profileType]=IOS_APP_STORE,IOS_APP_INHOUSE,IOS_APP_ADHOC,IOS_APP_DEVELOPMENT",
            "include": "bundleId",
            "limit": 200,
            "teamId": teamId,
        }
        r = self.session.post("https://developer.apple.com/services-account/v1/profiles", headers=headers, json=body)
        r.raise_for_status()
        data = r.json()

        return data

    def getBundleIds(self, teamId: str):
        headers = {
            "X-HTTP-Method-Override": "GET",
        }

        body: dict[str, Any] = {
            "teamId": teamId,
        }
        r = self.session.post("https://developer.apple.com/services-account/v1/bundleIds", headers=headers, json=body)
        r.raise_for_status()
        data = r.json()

        return data

    def getCertificates(self, teamId: str):
        headers = {
            "X-HTTP-Method-Override": "GET",
        }

        body: dict[str, Any] = {
            "teamId": teamId,
        }
        r = self.session.post(
            "https://developer.apple.com/services-account/v1/certificates", headers=headers, json=body
        )
        r.raise_for_status()
        data = r.json()

        return data

    def getDevices(self, teamId: str):
        headers = {
            "X-HTTP-Method-Override": "GET",
        }

        body: dict[str, Any] = {
            "urlEncodedQueryParams": "filter[platform]=IOS&filter[status]=ENABLED&limit=200",
            "teamId": teamId,
        }
        r = self.session.post("https://developer.apple.com/services-account/v1/devices", headers=headers, json=body)
        r.raise_for_status()
        data = r.json()

        return data

    def createProfile(self, profile: Config_Profile):
        if profile.certificateIds is None:
            raise ValueError("certificateIds must not be None")
        if profile.deviceIds is None:
            raise ValueError("deviceIds must not be None")
        if profile.teamId is None:
            raise ValueError("teamId must not be None")
        if profile.bundleId is None:
            raise ValueError("bundleId must not be None")

        name = profile.name.replace("%DATE%", datetime.datetime.now().strftime("%Y-%m-%d"))
        print(f"Creating profile: {name}")

        headers = {"Content-Type": "application/vnd.api+json"}
        certs = [{"type": "certificates", "id": certId} for certId in profile.certificateIds]
        devices = [{"type": "devices", "id": deviceId} for deviceId in profile.deviceIds]
        body: dict[str, Any] = {
            "data": {
                "attributes": {
                    "name": name,
                    "profileType": profile.profileType,
                    "templateName": profile.templateName,
                    "isOfflineProfile": profile.isOfflineProfile,
                    "teamId": profile.teamId,
                },
                "type": "profiles",
                "relationships": {
                    "bundleId": {"data": {"type": "bundleIds", "id": profile.bundleId}},
                    "certificates": {"data": certs},
                    "devices": {
                        "data": devices,
                    },
                },
            }
        }
        r = client.session.post("https://developer.apple.com/services-account/v1/profiles", headers=headers, json=body)
        r.raise_for_status()
        data = r.json()
        return data

    def deleteProfile(self, teamId: str, profileId: str):
        headers = {"X-HTTP-Method-Override": "DELETE"}
        body: dict[str, Any] = {
            "teamId": teamId,
        }
        r = self.session.post(
            f"https://developer.apple.com/services-account/v1/profiles/{profileId}", headers=headers, json=body
        )
        r.raise_for_status()
        # This doesn't return any data
        return True


if __name__ == "__main__":
    overall_success = True

    for cfg in config:
        username = cfg.user.username
        print(f"Logging in as {username}...")

        client = Client(cacheDirPath=f"./cache/{username}")

        response = client.login(username, cfg.user.password, cfg.two_factor_authentication)

        if not response:
            print(f"Login failed for {username}")
            continue

        print("Login successful")

        if not cfg.profiles:
            print(f"No profiles configured for {username}, skipping...")
            continue

        teams: list[dict[str, Any]] = client.getTeamsInfo()["teams"]
        bundles: dict[str, list[dict[str, Any]]] = {}
        for team in teams:
            bundles[team["teamId"]] = client.getBundleIds(team["teamId"])["data"]
        certificates: dict[str, list[dict[str, Any]]] = {}
        for team in teams:
            certificates[team["teamId"]] = client.getCertificates(team["teamId"])["data"]
        devices: dict[str, list[dict[str, Any]]] = {}
        for team in teams:
            devices[team["teamId"]] = client.getDevices(team["teamId"])["data"]

        abort = False
        if any([x.teamId is None for x in cfg.profiles]):
            print("List of team IDs")
            headers = ["Team ID"]
            data: list[list[str]] = []
            for team in teams:
                data.append([team["teamId"]])
            print(tabulate(data, headers=headers, tablefmt="grid"))
            print()
            abort = True

        if any([x.bundleId is None for x in cfg.profiles]):
            print("List of bundle IDs")
            headers = ["Team ID", "Bundle ID", "Name", "Identifier"]
            data: list[list[str]] = []
            for teamId in bundles:
                for b in bundles[teamId]:
                    data.append(
                        [
                            teamId,
                            b["id"],
                            b["attributes"]["name"],
                            b["attributes"]["identifier"],
                        ]
                    )
            print(tabulate(data, headers=headers, tablefmt="grid"))
            print()
            abort = True

        if any([x.certificateIds is None for x in cfg.profiles]):
            print("List of certificate IDs")
            headers = ["Team ID", "Certificate ID", "Owner", "Type", "Status"]
            data: list[list[str]] = []
            for teamId in certificates:
                for cert in certificates[teamId]:
                    data.append(
                        [
                            teamId,
                            cert["id"],
                            cert["attributes"]["ownerName"],
                            cert["attributes"]["certificateTypeName"],
                            cert["attributes"]["status"],
                        ]
                    )
            print(tabulate(data, headers=headers, tablefmt="grid"))
            print()
            abort = True

        if any([x.deviceIds is None for x in cfg.profiles]):
            print("List of device IDs")
            headers = ["Team ID", "Device ID", "Model", "Name", "Status"]
            data: list[list[str]] = []
            for teamId in devices:
                for device in devices[teamId]:
                    data.append(
                        [
                            teamId,
                            device["id"],
                            device["attributes"]["model"],
                            device["attributes"]["name"],
                            device["attributes"]["status"],
                        ]
                    )
            print(tabulate(data, headers=headers, tablefmt="grid"))
            print()
            abort = True

        if abort:
            continue

        for profile in cfg.profiles:
            if profile.teamId is None:
                raise ValueError("teamId must not be None")
            if profile.bundleId is None:
                raise ValueError("bundleId must not be None")
            if profile.certificateIds is None:
                raise ValueError("certificateIds must not be None")
            if profile.deviceIds is None:
                raise ValueError("deviceIds must not be None")

            if profile.teamId not in [x["teamId"] for x in teams]:
                raise ValueError(f"Team ID {profile.teamId} not found in teams list")
            if profile.bundleId not in [x["id"] for x in bundles[profile.teamId]]:
                raise ValueError(f"Bundle ID {profile.bundleId} not found in team {profile.teamId} bundles")
            if len(profile.certificateIds) == 0:
                raise ValueError(
                    f"Certificate IDs must not be empty for team {profile.teamId}, bundle {profile.bundleId}"
                )
            if set(profile.certificateIds).issubset(set([x["id"] for x in certificates[profile.teamId]])) is False:
                raise ValueError(
                    f"Certificate IDs {profile.certificateIds} not found in team {profile.teamId} certificates"
                )

            if len(profile.deviceIds) == 0:
                profile.deviceIds = [device["id"] for device in devices[profile.teamId]]
            if set(profile.deviceIds).issubset(set([x["id"] for x in devices[profile.teamId]])) is False:
                raise ValueError(f"Device IDs {profile.deviceIds} not found in team {profile.teamId} devices")

            try:
                client.createProfile(profile)
            except Exception:
                traceback.print_exc()
                overall_success = False

        for team in teams:
            teamId = team["teamId"]

            if cfg.options.deleteExpiredProfiles:
                print("TODO delete expired profiles")
                # First get all profiles
                # profiles = client.getProfiles(teamId)
                # find any where profileState is not ACTIVE
                # then delete
                # Not implemented as I don't have any expired profiles to test with

            profiles = client.getProfiles(teamId)

            for profile in profiles["data"]:
                profile_type = profile["attributes"]["profileType"]
                profile_uuid = profile["attributes"]["uuid"]
                name = profile["attributes"]["name"]
                type_name = pretty_type(profile_type)

                profile_name = f"{type_name}_{profile_uuid}_{name}.mobileprovision"

                print(f"Saving profile: {profile_name}")

                with open(profile_name, "wb") as f:
                    content = profile["attributes"]["profileContent"]
                    f.write(base64.b64decode(content))

    if overall_success is False:
        sys.exit(1)
