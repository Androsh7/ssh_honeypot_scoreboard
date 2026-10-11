# SSH Honeypot Scoreboard

A single-file python script that parses logs from https://github.com/droberson/ssh-honeypot and writes a JSON scoreboard for display on a website: the most common attacking IP addresses, usernames and passwords, plus per-IP statistics and geographic location.

## Requirements

Python 3.11 or newer and the `requests` package. Nothing else.

```bash
pip install requests
```

## Usage

```bash
python ssh_honeypot_scoreboard.py -i ssh-honeypot.log -c ip-location.cache -o scoreboard.json
```

| Option | Default | Meaning |
| --- | --- | --- |
| `-i`, `--honeypot-file` | required | The ssh-honeypot log to parse |
| `-o`, `--output-file` | required | The JSON file to write |
| `-c`, `--cache-file` | required | JSON cache of ipinfo.io lookups, created on first run |
| `-t`, `--token-file` | none | File containing an ipinfo.io access token |
| `--top-ips` | 25 | How many addresses to include (only these are looked up) |
| `--top-usernames` | 25 | How many usernames to include overall |
| `--top-passwords` | 25 | How many passwords to include overall |
| `--top-usernames-per-ip` | 10 | How many usernames to list per address |
| `--top-passwords-per-ip` | 10 | How many passwords to list per address |
| `-v`, `--verbose` | off | Log progress to stderr |

Locations come from https://ipinfo.io. Only the addresses on the scoreboard are looked up, and every answer is kept in the cache file, so repeated runs make no requests for addresses already seen. Without a token ipinfo.io allows roughly 1000 lookups per day, which is plenty for the default of 25. If you have a token, put it in a file on its own and pass `--token-file`; it is sent as a bearer header and never appears on the command line.

If a lookup fails the cache is still saved, the error is logged, and the script exits with status 1 without writing the output file.

## Output

```json
{
  "generated_at": "2026-10-11T22:00:00+00:00",
  "total_attempts": 311851,
  "unique_ips": 6718,
  "unique_usernames": 4000,
  "unique_passwords": 90000,
  "first_attempt": "2025-08-11T00:34:57",
  "last_attempt": "2026-10-11T12:00:00",
  "top_usernames": [{ "value": "root", "count": 150000 }],
  "top_passwords": [{ "value": "123456", "count": 5000 }],
  "top_ips": [
    {
      "ip": "1.2.3.4",
      "count": 20000,
      "first_seen": "2025-09-01T03:00:00",
      "last_seen": "2025-09-03T18:00:00",
      "unique_usernames": 12,
      "unique_passwords": 19000,
      "location": {
        "ip": "1.2.3.4",
        "city": "Brisbane",
        "region": "Queensland",
        "country": "AU",
        "loc": "-27.4679,153.0281",
        "timezone": "Australia/Brisbane",
        "hostname": "example.net",
        "org": "AS13335 Cloudflare, Inc.",
        "postal": "9010",
        "bogon": false,
        "time_queried": "2026-10-11T22:27:19+00:00"
      },
      "top_usernames": [{ "value": "root", "count": 19000 }],
      "top_passwords": [{ "value": "123456", "count": 40 }]
    }
  ]
}
```

Timestamps from the log are the honeypot host's local time and carry no timezone. `generated_at` and `time_queried` are UTC.

## Development

```bash
uv sync --extra dev
uv run ruff check --fix . && uv run ruff format .
uv run pytest
```
