# SaltStack ext_pillar Bitwarden

Custom external pillar module to retrieve secrets from Bitwarden and expose them as Salt pillar data.

---

## Requirements

* `jq` must be installed:

  ```bash
  apt-get install jq
  ```
* You must run this on the server hosting the `salt-master`
* The Bitwarden CLI must be installed
  Documentation: [https://bitwarden.com/help/cli/](https://bitwarden.com/help/cli/)

  Example installation (after zip download):

  ```bash
  mkdir -p /etc/salt/bitwarden
  unzip bw-linux.zip -d /etc/salt/bitwarden/
  ```

---

## Writing Bitwarden Secrets

Secrets are mapped to pillar paths using a naming convention.

### Example

If a user is named:

```
pillar:test:secret
```

Then the resulting pillar will be:

```yaml
{{ pillar_base }}:
  pillar:
    test:
      secret: <secret_value>
```

### Notes

* The **password field** is used as the secret value
* If no password is defined, the **notes field** is used instead, This allows storing **multiline secrets**
* You can also use `!notes` or `!password` at the end of **username**
* Finally you can use `!merge`, this will use **notes fields** and parse it as yaml

!merge example

```
username = "pillar:MyMergedNote!merge"

notes = """
role: ABC
appcode: APP
number: 01
"""
```

Then the resulting pillar will be:

```yaml
{{ pillar_base }}:
  pillar:
    MyMergedNote:
      role: ABC
      appcode: APP
      number: 01
```

---

## Conditional Access

Access to secrets can be restricted using custom fields in Bitwarden items.

### How it works

* The `minion_id_parse_pattern` extracts groups from the minion ID
  * The default one is : `(?P<appcode>.+?)(?P<role>.{3})(?P<number>\d{2})-(?P<env>.{3})\.(?P<domain>.+)`
  * It parse minion_id like `appcoderol01-dev.mydomain.com` => appcode=appcode, role=rol, number=01, env=dev, domain=mydomain.com
* These groups can be reused in Bitwarden item fields
* You define conditions using custom fields on each secret
* Multiple values are separated by `,` this works for any `group` or `minion_id` but not `pattern`
* Default operator is **AND**
* Use `op="or"` to split conditions with OR (AND operation have priority)

### Supported fields

| Field       | Description                     |
| ----------- | ------------------------------- |
| `minion_id` | Exact match                     |
| `pattern`   | Regex match                     |
| `<group>`   | Match extracted group           |
| `op`        | Logical operator (`and` / `or`) |


### Example

```
x = "1"
y = "test1,test2"
op = "or"
test = "true"
```

This evaluates as:

```
(x = "1" AND y in ["test1","test2"]) OR (test = "true")
```

> value are always strings

---

## Installation / Configuration (Salt Master)

### 1. Install the module

Copy the file `_pillar/bitwarden.py` and place it here:

```bash
/srv/salt/_pillar/bitwarden.py
```

Then sync custom pillar:

```bash
salt-run saltutil.sync_pillar
```

You should see:

```
pillar.bitwarden
```

Copy the file `_runner/bitwarden.py` and place it here:

```bash
/srv/salt/_runner/bitwarden.py
```

Then sync custom runners:

```bash
salt-run saltutil.sync_runners
```

You should see:

```
runners.bitwarden
```

---

### 2. Configure ext_pillar

Edit:

```
/etc/salt/master.d/bitwarden.conf
```

Add:

```yaml
ext_pillar:
  - bitwarden:

      # Required
      vault_url: 'vault.xxx.net'
      master_password: 'xxx'

      # Available in:
      # Vault → Profile → Security → Keys → API Key
      client_id: 'xxx'
      client_secret: 'xxx'

      # Optional

      # Filter secrets (same behavior as Bitwarden search bar)
      search: 'pillar:'

      # Path to Bitwarden CLI
      cli_path: '/etc/salt/bitwarden/bw'

      # Prefix in pillar (supports nesting like a:b:c)
      pillar_base: 'bitwarden'

      # Bitwarden CLI config directory
      appdata_dir: '/var/cache/salt/master/bitwarden-cli'

      # Regex to parse minion_id into groups
      # WARNING: Do not use group names: minion_id, pattern, op
      minion_id_parse_pattern: '(?P<appcode>.+?)(?P<role>.{3})(?P<number>\d{2})-(?P<env>.{3})\.(?P<domain>.+)'

      # Cache configuration
      cache_bank: 'ext_pillar/bitwarden'
      cache_ttl: 300
```

Restart Salt:

```bash
systemctl restart salt-master
```

### 3. Test

```bash
salt-run pillar.items
# OR
salt '*' pillar.items
```

---

## Cache info

### List cache

```bash
salt-run cache.list ext_pillar/bitwarden
```

### Cache structure

#### Master cache

```
ext_pillar/bitwarden/master
```

Contains:

* `last_sync` : last vault synchronization timestamp
* `pillar` : pillar data required to compile minion pillar
* `session_token` : Bitwarden session token

#### Important behavior

* `session_token` is **NOT affected by TTL**
* It is reused to avoid repeated `bw unlock`
* If expired : a new token is automatically generated
* `cache_ttl` applies to **pillar data** in order synchronise data with bitwarden

#### Minion cache

```
ext_pillar/bitwarden/minion/<minion_id>
```

Contains:

* Final computed pillar for each minion <minion_id>
* If not computed yet and `last_sync`+`ttl`<`now` use `ext_pillar/bitwarden/master/pillar`

#### Check and free cache

> doc : https://docs.saltproject.io/en/master/ref/cache/all/salt.cache.localfs_key.html

to check cache you use for example `salt-run cache.fecth ext_pillar/bitwarden/master pillar`

To recompute cache you multiple option, you can do:
* salt-run bitwarden.refresh_cache - Refresh cache with runner, that what ext_pillar does when needed
  * This is the recommanded way as you see parsing errors
* `salt-call pillar.items pillar='{bitwarden:need_sync: true}'` - Run pillar items, while requiring refresh
* salt-run cache.flush ext_pillar/bitwarden - Completely remove existing cache

`salt-run bitwarden.refresh_cache` Can be use in a systemd service to automatically reload cache, to be usefull the service timer need to be lower than **cache_ttl**.
Default **cache_ttl** is 5min, you can set it to 10 and run service with timer every 5min for example.
