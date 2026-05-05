# -*- coding: utf-8 -*-
from time import time as now
from typing import Any
import logging
import re

import salt.cache
from salt.utils.dictupdate import set_dict_key_value

LOG = logging.getLogger(__name__)
CACHE = None


def __virtual__():
    return "bitwarden"


def get_cache():
    """
    Lazy initialization of Salt cache object.

    Salt provides a cache backend (localfs, redis, etc).
    We reuse the same instance to avoid re-instantiating it everywhere.
    """
    global CACHE
    if CACHE is None:
        CACHE = salt.cache.Cache(__opts__)
    return CACHE


###################################################################
#
#   ext_pillar
#

def ext_pillar(minion_id, pillar, *args, **_kwargs):
    """
    Entry point called by Salt when building pillar.

    Goal:
    - DO NOT do heavy work here (no bw sync, no CLI calls)
    - ONLY read cache and compute minion-specific pillar

    If cache is invalid => delegate to runner
    """

    # Build runtime configuration from ext_pillar config
    env = {
        # Prefix added to all generated pillar keys
        "BW_PILLAR_BASE": _kwargs.get("pillar_base", "bitwarden"),

        # Regex used to extract metadata from minion_id
        # Example: appcode, role, env, etc.
        "MINION_ID_PARSE_PATTERN": re.escape(_kwargs.get(
            "minion_id_parse_pattern",
            "(?P<appcode>.+?)(?P<role>.{3})(?P<number>\d{2})-(?P<env>.{3})\.(?P<domain>.+)",
        )),

        # Cache location (namespace in Salt cache)
        "CACHE_BANK": _kwargs.get("cache_bank", "ext_pillar/bitwarden").strip("/"),

        # Cache TTL (seconds)
        "CACHE_TTL": int(_kwargs.get("cache_ttl", 60 * 5)),

        # Runner used to refresh cache (heavy logic)
        "RUNNER_FUN": _kwargs.get("runner_fun", "bitwarden.refresh_cache"),

        # Pass full config to runner
        "RUNNER_KWARGS": _kwargs,
    }

    # Allow forcing refresh via:
    # salt-call pillar.items pillar='{"bitwarden":{"need_sync":true}}'
    need_sync = pillar.get("bitwarden:need_sync", False) is True

    return build_minion_pillar_from_cache(
        minion_id=minion_id,
        env=env,
        need_sync=need_sync,
    )


###################################################################
#
#   Cache
#

def build_minion_pillar_from_cache(minion_id: str, env: dict, need_sync: bool = False) -> dict:
    """
    Main logic:

    1. Check if cache is valid
    2. If not => call runner to refresh
    3. Try to return cached minion pillar
    4. Otherwise compute it from master cache
    """

    cache = get_cache()
    bank = env["CACHE_BANK"]
    ttl = env["CACHE_TTL"]

    current_time = now()

    # Last time master cache was refreshed
    last_sync = cache.fetch(f"{bank}/master", "last_sync")

    # Cache is invalid if:
    # - never synced
    # - corrupted value
    # - expired (TTL exceeded)
    cache_invalid = (
        last_sync is None
        or not isinstance(last_sync, (int, float))
        or last_sync + ttl < current_time
    )

    # If forced or invalid => refresh cache using runner
    if need_sync or cache_invalid:
        refresh_cache_with_runner(env)

    # Try to return already computed minion pillar (fast path)
    if cache.contains(f"{bank}/minion", minion_id):
        return cache.fetch(f"{bank}/minion", minion_id)

    # Otherwise load master pillar (shared for all minions)
    pillar_items = cache.fetch(f"{bank}/master", "pillar_items")

    if not pillar_items:
        LOG.warning("No Bitwarden pillar items found in cache")
        return {}

    # Compute pillar specific to this minion
    minion_pillar = build_minion_pillar(
        pillar_items=pillar_items,
        minion_id=minion_id,
        env=env,
    )

    # Cache result for next call
    cache.store(f"{bank}/minion", minion_id, minion_pillar)

    return minion_pillar


def refresh_cache_with_runner(env: dict):
    """
    Delegate heavy work to runner:
    - bw login/unlock
    - bw sync
    - parsing vault
    - storing master cache

    ext_pillar must stay lightweight => runner handles everything expensive
    """
    result = __salt__["saltutil.runner"](
        env["RUNNER_FUN"],
        kwarg=env["RUNNER_KWARGS"],
    )

    if isinstance(result, dict) and result.get("result") is False:
        raise RuntimeError(f"Bitwarden cache refresh failed: {result}")

    return result


###################################################################
#
#   Pillar processing
#

def build_minion_pillar(pillar_items: list[dict], minion_id: str, env: dict) -> dict:
    """
    Transform shared 'master' data into minion-specific pillar.

    Steps:
    1. Extract context from minion_id (env, role, etc.)
    2. Evaluate conditions for each item
    3. Build final pillar structure
    """

    # Extract structured data from minion_id
    context = parse_minion_id(
        minion_id=minion_id,
        pattern=env["MINION_ID_PARSE_PATTERN"],
    )
    context["minion_id"] = minion_id

    result = {}

    for item in pillar_items:

        # Skip item if conditions don't match this minion
        if not compute_conditions(item.get("conditions", []), context):
            continue

        path = item["path"]

        # Apply global prefix (ex: bitwarden:...)
        pillar_base = env.get("BW_PILLAR_BASE")
        if pillar_base:
            path = f"{pillar_base.strip(':')}:{path}"

        # Insert value into nested dict using Salt helper
        # Example:
        # path = "bitwarden:db:user"
        # => creates nested structure automatically
        set_dict_key_value(result, path, item.get("value"))

    return result


###################################################################
#
#   Conditions
#

def compute_conditions(conditions: list[tuple[str, Any]], context: dict[str, Any]) -> bool:
    """
    Evaluate logical conditions attached to a secret.

    Supports:
    - AND (default)
    - OR (via 'op')
    - pattern (regex on minion_id)
    - equality / list matching

    Example:
        group1 <=> (cond1 and cond2 and ...)
        group2 <=> (condA and condB and ...)
        etc...
        
        conditions = [[cond1,cond2,...],[condA,condB,...],...]
        conditions <=> (cond1 and cond2 and ...) or (condA and condB and ...) or ...
        conditions <=> group1 or group2 or ...
 
    """

    groups = [[]]  # each group = AND conditions

    for key, value in conditions:

        # Logical operators
        if key == "op":
            if value == "or":
                groups.append([])  # start new OR group
            elif value == "and":
                continue
            else:
                LOG.warning("Unsupported operator: %s", value)
                return False
            continue

        # Regex match on minion_id
        if key == "pattern":
            groups[-1].append(
                lambda ctx, v=value: re.match(v, ctx["minion_id"]) is not None
            )
            continue

        # Handle single value or list
        values = [v.strip() for v in str(value).split(",")]

        if len(values) == 1:
            groups[-1].append(
                lambda ctx, k=key, v=values[0]: ctx.get(k) == v
            )
        else:
            groups[-1].append(
                lambda ctx, k=key, v=values: ctx.get(k) in v
            )

    # True if ANY group is fully valid
    return any(
        all(cond(context) for cond in group)
        for group in groups
    )


###################################################################
#
#   Utils
#

def parse_minion_id(minion_id: str, pattern: str) -> dict[str, str]:
    """
    Extract structured fields from minion_id using regex.

    Example:
        minion_id = app01-prd.domain
        => {appcode, role, env, ...}
    """
    match = re.match(pattern, minion_id)

    if not match:
        LOG.warning("Invalid minion_id format: %s", minion_id)
        return {}

    return match.groupdict()