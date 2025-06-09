#! /usr/bin/env python3

from dataclasses import dataclass


@dataclass
class Config_User:
    # Consider having these included as environment variables
    username: str
    password: str


@dataclass
class Config_Options:
    deleteExpiredProfiles: bool


@dataclass
class Config_2fa:
    # When 2FA is required, the app will call this script
    # and wait up to two minutes for it to return a value.
    # The script should return the 2FA code on stdout in JSON
    # format, e.g. {"code": "123456"}.
    # This can be used to fire an alert to the user via
    # a messaging app, for example.
    request_app: list[str]


@dataclass
class Config_Profile:
    # The name for the profile. Use tokens to make it unique each time.
    # Tokens:
    # %DATE% - Current date in YYYY-MM-DD format
    name: str

    # The type of profile. Possible values:
    # IOS_APP_DEVELOPMENT, IOS_APP_ADHOC, IOS_APP_INHOUSE, IOS_APP_APPSTORE
    profileType: str

    templateName: str | None

    isOfflineProfile: bool

    # The team ID to use. Set to None to list all teams.
    teamId: str | None

    # The bundle ID to use. Set to None to list all bundle ids.
    bundleId: str | None

    # The certificate IDs to use. Set to None to list all certificates.
    certificateIds: list[str] | None

    # The device IDs to use. Set to None to list all devices.
    # Set to an empty list to include all devices.
    deviceIds: list[str] | None


@dataclass
class Config:
    user: Config_User
    options: Config_Options
    two_factor_authentication: Config_2fa
    profiles: list[Config_Profile]
