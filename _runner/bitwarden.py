# -*- coding: utf-8 -*-
from dataclasses import dataclass, asdict
from contextlib import contextmanager
from typing import Any, Iterable
from time import time as now

import logging
import json
import re
import yaml
import os
import subprocess

import salt.config
import salt.cache

LOG = logging.getLogger(__name__)
CACHE = None


def __virtual__():
    return "bitwarden"


def get_cache():
    """
    Lazy initialization of Salt cache.
    """
    global CACHE
    if CACHE is None:
        CACHE = salt.cache.Cache(__opts__)
    return CACHE


###################################################################
#
#   Shell execution (REPLACES cmd.run_all)
#

def run_cmd(cmd: str, env: dict[str, str]) -> dict:
    """
    Execute shell command from runner.

    Why:
    - Runner runs on master
    - __salt__["cmd.run_all"] is NOT available here
    - So we use subprocess instead

    Behavior similar to cmd.run_all:
        return {
            retcode,
            stdout,
            stderr
        }
    """
    full_env = os.environ.copy()
    full_env.update(env)

    result = subprocess.run(
        cmd,
        shell=True,
        text=True,
        capture_output=True,
        env=full_env,
    )

    return {
        "retcode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


###################################################################
#
#   Classes
#

class BitwardenError(RuntimeError):
    pass


@dataclass
class PillarItem:
    uuid: str
    name: str
    path: str
    value: str | dict
    conditions: list[tuple[str, Any]]

    def to_cache(self) -> dict:
        return asdict(self)


class PillarItems(list[PillarItem]):

    def __init__(self, items: Iterable = ()):
        super().__init__(items)

    def to_cache(self) -> list[dict]:
        return [item.to_cache() for item in self]

    @classmethod
    def from_cli_output(cls, items: list[dict]) -> "PillarItems":
        pillar_items = cls()

        path_re = re.compile(
            r"^(?P<base>(?:[a-z0-9_-]+:)*[a-z0-9_-]+)(?:!(?P<suffix>password|notes|merge))?$",
            re.IGNORECASE,
        )

        for item in items:
            paths = item.get("path")

            if not paths:
                LOG.error("Invalid item path null/empty for item=%s", item)
                continue

            for raw_path in paths.split(","):
                raw_path = raw_path.strip()

                match = path_re.match(raw_path)
                if not match:
                    LOG.error("Invalid item path=%s item=%s", raw_path, item)
                    continue

                base_path = match.group("base")
                suffix = match.group("suffix")
                suffix = suffix.lower() if suffix else None

                if suffix == "password":
                    value = item.get("password")

                elif suffix == "notes":
                    value = item.get("notes")

                elif suffix == "merge":
                    value = parse_merge_yaml(item)
                    if value is None:
                        continue

                else:
                    value = item.get("password") or item.get("notes")

                pillar_items.append(
                    PillarItem(
                        uuid=item["uuid"],
                        name=item["name"],
                        path=base_path,
                        value=value,
                        conditions=item.get("conditions", []),
                    )
                )

        return pillar_items


@dataclass
class VaultSession:
    status: str
    env: dict[str, str]


###################################################################
#
#   Runner entrypoint
#

def refresh_cache(**kwargs) -> dict:
    env = build_env(kwargs)

    cache = get_cache()
    bank = env["CACHE_BANK"]

    old_items = cache.fetch(f"{bank}/master", "pillar_items")

    with vault_session(env) as vault:
        vault.bw_sync()
        pillar_items = vault.get_pillar_items().to_cache()

    changed = pillar_items != old_items

    cache.store(f"{bank}/master", "last_sync", now())

    if changed:
        cache.flush(f"{bank}/minion")
        cache.flush(f"{bank}/master", "pillar_items")
        cache.store(f"{bank}/master", "pillar_items", pillar_items)

    return {
        "result": True,
        "changed": changed,
        "count": len(pillar_items),
    }


###################################################################
#
#   Config
#

def build_env(kwargs: dict) -> dict[str, str]:
    config = read_bitwarden_master_config()

    merged = {}
    merged.update(config)
    merged.update(kwargs)

    required = [
        "vault_url",
        "client_id",
        "client_secret",
        "master_password",
    ]

    missing = [key for key in required if not merged.get(key)]
    if missing:
        raise BitwardenError(f"Missing required arguments: {missing}")

    return {
        "BW_VAULT_URL": merged["vault_url"],
        "BW_CLIENTID": merged["client_id"],
        "BW_CLIENTSECRET": merged["client_secret"],
        "BW_MASTERPASSWORD": merged["master_password"],
        "BW_SEARCH": merged.get("search", "pillar:"),
        "BW_CLI_PATH": merged.get("cli_path", "/etc/salt/bitwarden/bw"),
        "BITWARDENCLI_APPDATA_DIR": merged.get(
            "appdata_dir",
            "/var/cache/salt/master/bitwarden-cli",
        ),
        "CACHE_BANK": merged.get("cache_bank", "ext_pillar/bitwarden").strip("/"),
    }


def read_bitwarden_master_config() -> dict:
    path = "/etc/salt/master.d/bitwarden.conf"

    try:
        data = salt.config.load_config(
            path,
            "SALT_EXT_PILLAR_BITWARDEN_CONFIG",
            default_path=path,
        )
    except Exception as exc:
        LOG.warning("Failed to read %s: %s", path, exc)
        return {}

    ext_pillar = data.get("ext_pillar", [])

    for item in ext_pillar:
        if isinstance(item, dict) and isinstance(item.get("bitwarden"), dict):
            return item["bitwarden"]

    return {}


###################################################################
#
#   Commands
#

# Decorator to add command to VaultSession as method
def vault_session_extend(func):
    def method(self, *args, **kwargs):
        return func(self.env, *args, **kwargs)

    setattr(VaultSession, func.__name__, method)
    return func


@vault_session_extend
def bw_status(env: dict[str, str]) -> str:
    result = run_cmd('"$BW_CLI_PATH" status', env)

    if result["retcode"] != 0:
        raise BitwardenError(result["stderr"] or result["stdout"])

    return result["stdout"]


@vault_session_extend
def bw_sync(env: dict[str, str]) -> str:
    result = run_cmd('"$BW_CLI_PATH" sync', env)

    if result["retcode"] != 0:
        raise BitwardenError(result["stderr"] or result["stdout"])

    return result["stdout"]


@vault_session_extend
def get_pillar_items(env: dict[str, str]) -> PillarItems:
    cmd = r'''
"$BW_CLI_PATH" list items --search "$BW_SEARCH" \
| jq '[.[] | {
    uuid: .id,
    name: .name,
    path: .login.username,
    password: .login.password,
    notes: .notes,
    conditions: (
      (.fields // [])
      | map([.name, .value])
    )
}]'
'''

    result = run_cmd(cmd, env)

    if result["retcode"] != 0:
        raise BitwardenError(result["stderr"] or result["stdout"])

    parsed = json.loads(result["stdout"])
    return PillarItems.from_cli_output(parsed)


###################################################################
#
#   Vault
#

@contextmanager
def vault_session(env: dict):
    status = bw_status(env)

    if '"status":"unauthenticated"' in status:
        run_cmd(
            '"$BW_CLI_PATH" config server "$BW_VAULT_URL" && "$BW_CLI_PATH" login --apikey',
            env,
        )
        status = bw_status(env)

    if '"status":"unlocked"' not in status:
        result = run_cmd(
            '"$BW_CLI_PATH" unlock --passwordenv BW_MASTERPASSWORD --raw',
            env,
        )

        if result["retcode"] != 0:
            raise BitwardenError(result["stderr"] or result["stdout"])

        env["BW_SESSION"] = result["stdout"].strip()

    yield VaultSession(status=status, env=env)


###################################################################
#
#   !Merge
#

def parse_merge_yaml(item: dict) -> dict | None:
    notes = item.get("notes")

    if not notes:
        LOG.error("Cannot merge empty notes for item=%s", item)
        return None

    try:
        data = yaml.safe_load(notes)
    except Exception as exc:
        LOG.error("Invalid YAML for item=%s: %s", item, exc)
        return None

    if not isinstance(data, dict):
        LOG.error("YAML merge must produce a dict for item=%s", item)
        return None

    return data