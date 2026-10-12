"""Generate a JSON scoreboard from the logs of https://github.com/droberson/ssh-honeypot"""

# Standard libraries
import argparse
import json
import logging
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

# Third-party libraries
import requests

logger = logging.getLogger(__name__)

LOG_LINE_PATTERN = re.compile(
    r"^\[(?P<timestamp>[A-Za-z]{3} [A-Za-z]{3} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4})\] "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) "
    r"(?P<username>\S+) "
    r"(?P<password>.*)$"
)
LOG_TIMESTAMP_FORMAT = "%a %b %d %H:%M:%S %Y"
LOG_ENCODING = "utf-8"
LINE_TERMINATORS = "\r\n"
EXCLUDED_IPS = frozenset({"127.0.0.1"})
IP_INFO_URL_TEMPLATE = "https://ipinfo.io/{ip}/json"
DEFAULT_LOOKUP_TIMEOUT_S = 5
DEFAULT_TOP_IP_COUNT = 25
DEFAULT_TOP_USERNAME_COUNT = 25
DEFAULT_TOP_PASSWORD_COUNT = 25
DEFAULT_TOP_USERNAMES_PER_IP = 10
DEFAULT_TOP_PASSWORDS_PER_IP = 10
FILE_ENCODING = "utf-8"
LOGGING_FORMAT = "%(asctime)s %(levelname)s %(message)s"
EXIT_SUCCESS = 0
EXIT_FAILURE = 1


class ScoreboardError(Exception):
    """Base error for every failure while building the scoreboard"""


class IpLocationLookupError(ScoreboardError):
    """Raised when ipinfo.io cannot be reached or rejects the request"""


class IpLocationCacheError(ScoreboardError):
    """Raised when the cache file cannot be read as a location cache"""


@dataclass
class HoneypotLogLine:
    """Record one login attempt against the honeypot"""

    timestamp: datetime
    ip: str
    username: str
    password: str

    @classmethod
    def parse(cls, line: str):
        """Return the login attempt recorded on one log line, or None when the line records something else

        Args:
            line: One line of the honeypot log, with or without its line terminator

        Returns:
            The login attempt, or None for startup messages, HASSH fingerprints and other non-attempt lines
        """
        match = LOG_LINE_PATTERN.match(line.rstrip(LINE_TERMINATORS))
        if match is None:
            return None
        return cls(
            timestamp=datetime.strptime(match.group("timestamp"), LOG_TIMESTAMP_FORMAT),
            ip=match.group("ip"),
            username=match.group("username"),
            password=match.group("password"),
        )


@dataclass
class HoneypotLog:
    """Hold every login attempt parsed from a honeypot log file"""

    lines: list[HoneypotLogLine] = field(default_factory=list)

    @classmethod
    def load(cls, log_path: Path, excluded_ips: frozenset[str] = EXCLUDED_IPS):
        """Return the login attempts recorded in a honeypot log file, in file order

        Args:
            log_path: The ssh-honeypot log file to read
            excluded_ips: Addresses whose attempts are left out

        Raises:
            FileNotFoundError: If the log file does not exist
        """
        lines = []
        excluded_count = 0
        with log_path.open(mode="r", encoding=LOG_ENCODING, errors="replace") as log_file:
            for raw_line in log_file:
                parsed_line = HoneypotLogLine.parse(raw_line)
                if parsed_line is None:
                    continue
                if parsed_line.ip in excluded_ips:
                    excluded_count += 1
                    continue
                lines.append(parsed_line)
        logger.info("Parsed %s login attempts from %s, excluded %s", len(lines), log_path, excluded_count)
        return cls(lines=lines)

    def lines_by_ip(self) -> dict[str, list[HoneypotLogLine]]:
        """Return the login attempts grouped by the address they came from

        Returns:
            One list per address, each in file order
        """
        grouped: dict[str, list[HoneypotLogLine]] = {}
        for line in self.lines:
            grouped.setdefault(line.ip, []).append(line)
        return grouped


@dataclass
class IpLocation:
    """Describe where one IP address is located, as reported by ipinfo.io"""

    ip: str
    city: str | None = None
    region: str | None = None
    country: str | None = None
    loc: str | None = None
    timezone: str | None = None
    hostname: str | None = None
    org: str | None = None
    postal: str | None = None
    bogon: bool = False
    time_queried: datetime = field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def from_dict(cls, location_dict: dict[str, Any]):
        """Return the location described by an ipinfo.io response or a cache entry

        Args:
            location_dict: The decoded JSON object

        Raises:
            KeyError: If the object has no ip field
        """
        time_queried = location_dict.get("time_queried")
        return cls(
            ip=location_dict["ip"],
            city=location_dict.get("city"),
            region=location_dict.get("region"),
            country=location_dict.get("country"),
            loc=location_dict.get("loc"),
            timezone=location_dict.get("timezone"),
            hostname=location_dict.get("hostname"),
            org=location_dict.get("org"),
            postal=location_dict.get("postal"),
            bogon=bool(location_dict.get("bogon", False)),
            time_queried=datetime.fromisoformat(time_queried) if time_queried else datetime.now(UTC),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the location as a JSON-serialisable object"""
        location_dict = asdict(self)
        location_dict["time_queried"] = self.time_queried.isoformat()
        return location_dict


class IpLocationProvider(Protocol):
    """Describe the one operation the cache needs from a location service"""

    def lookup(self, ip: str) -> IpLocation:
        """Return the location of one IP address

        Args:
            ip: The address to locate

        Raises:
            IpLocationLookupError: If the service cannot answer
        """
        ...


@dataclass
class IpInfoClient:
    """Query ipinfo.io over HTTP"""

    token: str | None = None
    timeout_s: int = DEFAULT_LOOKUP_TIMEOUT_S

    def lookup(self, ip: str) -> IpLocation:
        """Return the location ipinfo.io reports for one IP address

        Args:
            ip: The address to locate

        Raises:
            IpLocationLookupError: If the request fails, is rejected, or returns a body that is not a location
        """
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        try:
            response = requests.get(IP_INFO_URL_TEMPLATE.format(ip=ip), headers=headers, timeout=self.timeout_s)
            response.raise_for_status()
            location = IpLocation.from_dict(response.json())
        except (requests.RequestException, ValueError, KeyError) as error:
            raise IpLocationLookupError(f"Could not look up {ip}") from error
        logger.info("Looked up %s on ipinfo.io", ip)
        return location


@dataclass
class IpLocationCache:
    """Hold IP locations in memory and persist them to a JSON file between runs"""

    cache_path: Path
    provider: IpLocationProvider
    locations: dict[str, IpLocation] = field(default_factory=dict)

    @classmethod
    def load(cls, cache_path: Path, provider: IpLocationProvider):
        """Return a cache filled from the cache file, or an empty one when the file does not exist yet

        Args:
            cache_path: The JSON file the cache is read from and later saved to
            provider: The service consulted for addresses the file does not hold

        Raises:
            IpLocationCacheError: If the file exists but is not a valid cache
        """
        if not cache_path.exists():
            return cls(cache_path=cache_path, provider=provider)
        try:
            cache_dict = json.loads(cache_path.read_text(encoding=FILE_ENCODING))
            locations = {ip: IpLocation.from_dict(location) for ip, location in cache_dict.items()}
        except (ValueError, AttributeError, KeyError, TypeError) as error:
            raise IpLocationCacheError(f"{cache_path} is not a valid location cache") from error
        logger.info("Loaded %s cached locations from %s", len(locations), cache_path)
        return cls(cache_path=cache_path, provider=provider, locations=locations)

    def save(self) -> None:
        """Write every known location to the cache file"""
        cache_dict = {ip: location.to_dict() for ip, location in self.locations.items()}
        self.cache_path.write_text(json.dumps(cache_dict), encoding=FILE_ENCODING)
        logger.info("Saved %s locations to %s", len(cache_dict), self.cache_path)

    def locate(self, ip: str) -> IpLocation:
        """Return the location of one address, consulting the provider only when the cache lacks it

        Args:
            ip: The address to locate

        Raises:
            IpLocationLookupError: If the address is not cached and the provider cannot answer
        """
        if (location := self.locations.get(ip)) is not None:
            return location
        location = self.provider.lookup(ip)
        self.locations[ip] = location
        return location


@dataclass
class CountEntry:
    """Pair one value with how many times it was seen"""

    value: str
    count: int


@dataclass
class IpSummary:
    """Summarise everything one attacking address did"""

    ip: str
    count: int
    first_seen: datetime
    last_seen: datetime
    unique_usernames: int
    unique_passwords: int
    location: IpLocation | None
    top_usernames: list[CountEntry]
    top_passwords: list[CountEntry]

    @classmethod
    def from_lines(
        cls,
        ip: str,
        lines: list[HoneypotLogLine],
        location: IpLocation | None,
        top_usernames_per_ip: int,
        top_passwords_per_ip: int,
    ):
        """Return the per-address statistics for one attacker

        Args:
            ip: The address being summarised
            lines: Every login attempt made from that address, at least one
            location: Where the address is, or None when it could not be located
            top_usernames_per_ip: The most usernames to list for the address
            top_passwords_per_ip: The most passwords to list for the address
        """
        username_counts = Counter(line.username for line in lines)
        password_counts = Counter(line.password for line in lines)
        timestamps = [line.timestamp for line in lines]
        return cls(
            ip=ip,
            count=len(lines),
            first_seen=min(timestamps),
            last_seen=max(timestamps),
            unique_usernames=len(username_counts),
            unique_passwords=len(password_counts),
            location=location,
            top_usernames=most_common_entries(username_counts, top_usernames_per_ip),
            top_passwords=most_common_entries(password_counts, top_passwords_per_ip),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the summary as a JSON-serialisable object"""
        return {
            "ip": self.ip,
            "count": self.count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "unique_usernames": self.unique_usernames,
            "unique_passwords": self.unique_passwords,
            "location": self.location.to_dict() if self.location is not None else None,
            "top_usernames": [asdict(entry) for entry in self.top_usernames],
            "top_passwords": [asdict(entry) for entry in self.top_passwords],
        }


@dataclass
class Scoreboard:
    """Hold the complete summary written to the output file"""

    total_attempts: int
    unique_ips: int
    unique_usernames: int
    unique_passwords: int
    first_attempt: datetime | None
    last_attempt: datetime | None
    top_ips: list[IpSummary]
    top_usernames: list[CountEntry]
    top_passwords: list[CountEntry]
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def from_honeypot_log(
        cls,
        log: HoneypotLog,
        location_cache: IpLocationCache,
        top_ip_count: int = DEFAULT_TOP_IP_COUNT,
        top_username_count: int = DEFAULT_TOP_USERNAME_COUNT,
        top_password_count: int = DEFAULT_TOP_PASSWORD_COUNT,
        top_usernames_per_ip: int = DEFAULT_TOP_USERNAMES_PER_IP,
        top_passwords_per_ip: int = DEFAULT_TOP_PASSWORDS_PER_IP,
    ):
        """Return the scoreboard for a log, locating only the addresses that appear on it

        Args:
            log: The parsed honeypot log
            location_cache: The cache used to locate the top addresses
            top_ip_count: How many addresses to include
            top_username_count: How many usernames to include overall
            top_password_count: How many passwords to include overall
            top_usernames_per_ip: How many usernames to list for each address
            top_passwords_per_ip: How many passwords to list for each address

        Raises:
            IpLocationLookupError: If a top address is not cached and cannot be looked up
        """
        lines_by_ip = log.lines_by_ip()
        ip_counts = Counter({ip: len(ip_lines) for ip, ip_lines in lines_by_ip.items()})
        username_counts = Counter(line.username for line in log.lines)
        password_counts = Counter(line.password for line in log.lines)
        timestamps = [line.timestamp for line in log.lines]
        top_ips = [
            IpSummary.from_lines(
                ip=ip,
                lines=lines_by_ip[ip],
                location=location_cache.locate(ip),
                top_usernames_per_ip=top_usernames_per_ip,
                top_passwords_per_ip=top_passwords_per_ip,
            )
            for ip, _count in ip_counts.most_common(top_ip_count)
        ]
        return cls(
            total_attempts=len(log.lines),
            unique_ips=len(ip_counts),
            unique_usernames=len(username_counts),
            unique_passwords=len(password_counts),
            first_attempt=min(timestamps) if timestamps else None,
            last_attempt=max(timestamps) if timestamps else None,
            top_ips=top_ips,
            top_usernames=most_common_entries(username_counts, top_username_count),
            top_passwords=most_common_entries(password_counts, top_password_count),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the scoreboard as a JSON-serialisable object"""
        return {
            "generated_at": self.generated_at.isoformat(),
            "total_attempts": self.total_attempts,
            "unique_ips": self.unique_ips,
            "unique_usernames": self.unique_usernames,
            "unique_passwords": self.unique_passwords,
            "first_attempt": self.first_attempt.isoformat() if self.first_attempt is not None else None,
            "last_attempt": self.last_attempt.isoformat() if self.last_attempt is not None else None,
            "top_ips": [ip_summary.to_dict() for ip_summary in self.top_ips],
            "top_usernames": [asdict(entry) for entry in self.top_usernames],
            "top_passwords": [asdict(entry) for entry in self.top_passwords],
        }

    def save(self, output_path: Path) -> None:
        """Write the scoreboard to a JSON file

        Args:
            output_path: The file to write
        """
        output_path.write_text(json.dumps(self.to_dict()), encoding=FILE_ENCODING)
        logger.info("Wrote scoreboard to %s", output_path)


def most_common_entries(counter: Counter[str], limit: int) -> list[CountEntry]:
    """Return the most frequent values in a counter, most frequent first

    Args:
        counter: The values and their counts
        limit: The most entries to return

    Returns:
        At most `limit` entries, ordered from most to least frequent
    """
    return [CountEntry(value=value, count=count) for value, count in counter.most_common(limit)]


def build_argument_parser() -> argparse.ArgumentParser:
    """Return the command line parser

    Returns:
        A parser whose namespace holds every option the program needs
    """
    parser = argparse.ArgumentParser(
        prog="ssh_honeypot_scoreboard.py",
        description="Generate a JSON scoreboard from the logs of https://github.com/droberson/ssh-honeypot",
    )
    parser.add_argument("--honeypot-file", "-i", required=True, type=Path, help="The honeypot log file to parse")
    parser.add_argument("--output-file", "-o", required=True, type=Path, help="The JSON file to write")
    parser.add_argument("--cache-file", "-c", required=True, type=Path, help="The ipinfo.io location cache file")
    parser.add_argument("--token-file", "-t", type=Path, help="A file holding an ipinfo.io access token")
    parser.add_argument("--top-ips", type=int, default=DEFAULT_TOP_IP_COUNT, help="How many addresses to include")
    parser.add_argument(
        "--top-usernames", type=int, default=DEFAULT_TOP_USERNAME_COUNT, help="How many usernames to include"
    )
    parser.add_argument(
        "--top-passwords", type=int, default=DEFAULT_TOP_PASSWORD_COUNT, help="How many passwords to include"
    )
    parser.add_argument(
        "--top-usernames-per-ip",
        type=int,
        default=DEFAULT_TOP_USERNAMES_PER_IP,
        help="How many usernames to list per address",
    )
    parser.add_argument(
        "--top-passwords-per-ip",
        type=int,
        default=DEFAULT_TOP_PASSWORDS_PER_IP,
        help="How many passwords to list per address",
    )
    parser.add_argument(
        "--exclude-ip",
        "-x",
        action="append",
        default=sorted(EXCLUDED_IPS),
        metavar="IP",
        help="An address whose attempts are left out; repeat for several (127.0.0.1 is always excluded)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Log progress to stderr")
    return parser


def main(argument_list: list[str] | None = None) -> int:
    """Parse the honeypot log and write the scoreboard JSON

    Args:
        argument_list: The command line arguments, or None to read them from the process

    Returns:
        The process exit code
    """
    arguments = build_argument_parser().parse_args(argument_list)
    logging.basicConfig(level=logging.INFO if arguments.verbose else logging.WARNING, format=LOGGING_FORMAT)
    token = arguments.token_file.read_text(encoding=FILE_ENCODING).strip() if arguments.token_file else None
    try:
        log = HoneypotLog.load(arguments.honeypot_file, excluded_ips=frozenset(arguments.exclude_ip))
        location_cache = IpLocationCache.load(arguments.cache_file, provider=IpInfoClient(token=token))
    except (OSError, ScoreboardError):
        logger.exception("Could not load the inputs")
        return EXIT_FAILURE
    try:
        scoreboard = Scoreboard.from_honeypot_log(
            log=log,
            location_cache=location_cache,
            top_ip_count=arguments.top_ips,
            top_username_count=arguments.top_usernames,
            top_password_count=arguments.top_passwords,
            top_usernames_per_ip=arguments.top_usernames_per_ip,
            top_passwords_per_ip=arguments.top_passwords_per_ip,
        )
    except ScoreboardError:
        logger.exception("Could not build the scoreboard")
        return EXIT_FAILURE
    finally:
        location_cache.save()
    scoreboard.save(arguments.output_file)
    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())
