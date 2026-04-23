#/srv/salt/_pillar/bitwarden.py
from dataclasses import dataclass, asdict
from contextlib  import contextmanager
from pathlib     import Path
from typing      import Any, Callable, Iterable
from time        import time as now

import logging
import os
import json
import re

from salt.utils.dictupdate import set_dict_key_value
import salt.cache

LOG   = logging.getLogger(__name__)
CACHE = None

def get_cache():
    global CACHE
    if CACHE is None: 
        CACHE = salt.cache.Cache(__opts__)
    return CACHE

###################################################################
#
#   Classes
#

class BitwardenError(RuntimeError):
    pass

@dataclass
class PillarItem:
    name:  str # comment
    path:  str # path to secret in pillar
    value: str # secret value
    when_expr: list[tuple[str, Any]] # secret access conditions
    
    # ---- serialization ----
    def to_cache(self) -> dict:
        return asdict(self)

    @classmethod
    def from_cache(cls, data: dict) -> "PillarItem":
        return cls(**data)
    
class PillarItems(list):
    def __init__(self, items: Iterable = ()):
        super().__init__(items)

    # ---- serialization ----
    def to_cache(self) -> list[dict]:
        return [item.to_cache() for item in self]

    @classmethod
    def from_cache(cls, data: list[dict]) -> "PillarItems":
        return cls(PillarItem.from_cache(x) for x in data)


@dataclass
class VaultSession:
    status: str
    env: dict[str, str]

def ext_pillar(minion_id, pillar, *args, **_kwargs):
    env = {
        # Required
        'BW_VAULT_URL':      _kwargs['vault_url'],
        'BW_CLIENTID':       _kwargs['client_id'],
        'BW_CLIENTSECRET':   _kwargs['client_secret'],
        'BW_MASTERPASSWORD': _kwargs['master_password'],
        
        # Optionnal
        'BW_PILLAR_BASE':           _kwargs.get(
            'pillar_base', 'bitwarden'
        ),
        'BW_SEARCH':                _kwargs.get(
            'search', 'pillar:'
        ),
        'BW_CLI_PATH':              _kwargs.get(
            'cli_path', '/etc/salt/bitwarden/bw'
        ),
        'BITWARDENCLI_APPDATA_DIR': _kwargs.get(
            'appdata_dir',
            '/var/cache/salt/master/bitwarden-cli'
        ),
        'MINION_ID_PARSE_PATTERN':  _kwargs.get(
            # Must not use group named 'minion_id', 'pattern' or 'op'
            'miniond_id_parse_pattern',
            '(?P<appcode>.+?)(?P<role>.{3})(?P<number>\d{2})-(?P<env>.{3})\.(?P<domain>.+)'
        ),
        'CACHE_BANK': _kwargs.get('cache_bank', 'ext_pillar/bitwarden').strip('/'),
        'CACHE_TTL':  _kwargs.get('cache_ttl', 60 * 5),
    }

    minion_pillar: dict = build_minion_pillar_from_cache(
        minion_id=minion_id,
        env=env,
    )
    
    return minion_pillar

###################################################################
#
#   Utils
#

def parse_minion_id(minion_id: str, pattern: str) -> dict[str, str]:
    m = re.match(pattern, minion_id)
    if not m: 
        LOG.warn(f'Invalid minion_id format: {minion_id}')
        return {}

    return m.groupdict()

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
    result = __salt__['cmd.run_all'](
        '$BW_CLI_PATH status',
        env=env,
        python_shell=True,
    )
    return result['stdout']

@vault_session_extend
def bw_sync(env: dict[str, str]) -> str:
    result = __salt__['cmd.run_all'](
        '$BW_CLI_PATH sync',
        env=env,
        python_shell=True,
    )
    return result['stdout']

@vault_session_extend
def bw_seconds_since_last_sync(env: dict[str, str]) -> int:
    cmd    = r'echo $(( $(date +%s) - $(date -d "$($BW_CLI_PATH sync --last)" +%s) ))'
    result = __salt__['cmd.run_all'](cmd, env=env, python_shell=True)
    return int(result['stdout'])

@vault_session_extend
def get_pillar_items(env: dict[str, str]) -> PillarItems:
    # list items and filter with jq
    # password is used as value, if None, then use notes
    # notes allow multilines content
    cmd = r"""
$BW_CLI_PATH list items --search "$BW_SEARCH" \
| jq '[.[] | {
    name: .name,
    path: .login.username,
    value: (.login.password // .notes // ""),
    when_expr: (
      (.fields // [])
      | map([.name, .value])
    )
}]'
"""
    result = __salt__['cmd.run_all'](cmd, env=env, python_shell=True)
    parsed = json.loads(result['stdout'])

    pillar_items = [PillarItem(**item) for item in parsed]
    return PillarItems(pillar_items)

###################################################################
#
#   vault
#

@contextmanager
def vault_session(env: dict = None):

    try:
        status = bw_status(env)

        if '"status":"unlocked"' in status:
            yield VaultSession(env=env, status=status)
            return
        
        if '"status":"unauthenticated"' in status:
            __salt__['cmd.run_all'](
                '$BW_CLI_PATH config server "$BW_VAULT_URL"; $BW_CLI_PATH login --apikey', 
                env=env, 
                python_shell=True,
            )
            status = bw_status(env)
        
        result = __salt__['cmd.run_all'](
            '$BW_CLI_PATH unlock --passwordenv BW_MASTERPASSWORD --raw',
            env=env,
            python_shell=True,
        )
        session_token = result['stdout']
        if not session_token:
            raise BitwardenError('Failed to retrieve BW_SESSION from bw unlock')

        env['BW_SESSION'] = session_token

        yield VaultSession(env=env, status=status)
        
    finally: pass

###################################################################
#
#   pillar processing
#

def build_master_pillar(env:dict) -> PillarItems:
    with vault_session(env=env) as v:
        v.bw_sync()
        pillar_items = v.get_pillar_items()
    return pillar_items

def build_minion_pillar(pillar_items:PillarItems, minion_id:str, env:dict) -> dict:
    context : dict[str, str] = parse_minion_id(
        minion_id=minion_id,
        pattern=env['MINION_ID_PARSE_PATTERN'],
    )
    context['minion_id'] = minion_id
    
    _pillar = {}
    for pillar_item in pillar_items:
        if compute_when(
            when_expr=pillar_item.when_expr,
            context=context,
        ): 
            path = pillar_item.path
            # Pillar prefix only added to minion
            # so it can be change without needing to flush cache
            if pillar_base:=env['BW_PILLAR_BASE']:
                path = pillar_base.strip(':')+':'+path
                
            set_dict_key_value(_pillar, path, pillar_item.value)
    
    return _pillar

def build_minion_pillar_from_cache(minion_id: str, env: dict) -> dict:
    """
    master/pillar store PillarItems, used to compute minion pillar
    minion/minion_id store dict = computed pillar
    """
    CACHE = get_cache()
    bank = env["CACHE_BANK"]
    ttl  = env["CACHE_TTL"]
    current_time = now()
    skip_fetch = False
    try:
        session_token  = CACHE.fetch(bank + '/master', 'session_token')
        last_sync_time = CACHE.fetch(bank + '/master', 'last_sync')
    except: 
        last_sync_time = None
        session_token  = None
    if (
        last_sync_time is None
        or not isinstance(last_sync_time, (int, float))
        or last_sync_time + ttl < current_time
    ): # Flush CACHE if invalid time or too old
        CACHE.flush(bank + '/minion')
        CACHE.flush(bank + '/master', 'pillar')
        skip_fetch = True

    env["BW_SESSION"] = session_token
    master_pillar = None
    if not skip_fetch:
        master_pillar = CACHE.fetch(bank + '/master', 'pillar')
        master_pillar = PillarItems.from_cache(master_pillar) if master_pillar else None
    if master_pillar is None:
        # Build master_pillar and store it for next time
        master_pillar = build_master_pillar(env=env)
        CACHE.store(bank + '/master', 'pillar', master_pillar.to_cache())
        CACHE.store(bank + '/master', 'last_sync', current_time)

    minion_pillar = None
    if not skip_fetch:
        minion_pillar: dict = CACHE.fetch(bank + '/minion', minion_id)
    if minion_pillar: return minion_pillar

    # Build minion_pillar from master_pillar and store it for next time
    minion_pillar = build_minion_pillar(pillar_items=master_pillar, minion_id=minion_id, env=env)
    CACHE.store(bank + '/minion', minion_id, minion_pillar)
    
    return minion_pillar


def compute_when(when_expr: list[tuple[str, str]], context: dict[str, Any]) -> bool:
    groups = [[]]  # list of AND-groups 
    """Example
    group1 <=> (cond1 and cond2 and ...)
    group2 <=> (condA and condB and ...)
    etc...
    
    groups <=> group1 or group2 or ...
    groups <=> (cond1 and cond2 and ...) or (condA and condB and ...) or ...
    groups = [[cond1,cond2,...],[condA,condB,...],...]
    """

    for key, value in when_expr:
        
        # Operators : default=and
        if key == 'op':
            if   value == 'or' : groups.append([])  # start new group
            elif value == 'and': continue
            else: raise ValueError(f'Unsupported operator: {value}')
            continue
        
        # Filter Functions
        if key == 'pattern':
            groups[-1].append(
                lambda ctx, v=value: re.match(v, ctx['minion_id']) is not None
            )
            continue

        values = [v.strip() for v in value.split(",")]
        if len(values) == 1:
            groups[-1].append( lambda ctx, k=key, v=values[0]: ctx.get(k) == v )
        else: # list handling
            groups[-1].append( lambda ctx, k=key, v=values: ctx.get(k) in v )

    return any(
        all(cond(context) for cond in group)
        for group in groups
    )
