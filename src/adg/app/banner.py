import sys
from importlib.metadata import PackageNotFoundError, version

BANNER = r"""
           _                                              _
 ___  __ _| | __ ___      __      _____  _____  ___ _   _| |_ ___  _ __
/ __|/ _` | |/ _` \ \ /\ / /____ / _ \ \/ / _ \/ __| | | | __/ _ \| '__|
\__ \ (_| | | (_| |\ V  V /_____|  __/>  <  __/ (__| |_| | || (_) | |
|___/\__, |_|\__, | \_/\_/       \___/_/\_\___|\___|\__,_|\__\___/|_|
        |_|  |___/
"""


def print_banner() -> None:
    try:
        app_version = version("ai-data-access-gateway")
    except PackageNotFoundError:
        app_version = "dev"
    footer = f" :: SQL Gateway executor ::              (v{app_version})\n"
    sys.stdout.write(BANNER.lstrip("\n") + footer)
    sys.stdout.flush()
