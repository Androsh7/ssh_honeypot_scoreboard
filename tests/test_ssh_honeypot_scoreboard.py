"""Test the honeypot scoreboard script"""

# Standard libraries
import json
from datetime import datetime
from pathlib import Path

# Third-party libraries
import pytest
import responses

# Project libraries
from ssh_honeypot_scoreboard import (
    HoneypotLog,
    HoneypotLogLine,
    IpInfoClient,
    IpLocation,
    IpLocationCache,
    IpLocationLookupError,
    Scoreboard,
    main,
)

HTTP_OK = 200
HTTP_TOO_MANY_REQUESTS = 429


class FakeIpLocationProvider:
    """Answer lookups from memory and remember which addresses were asked for"""

    def __init__(self):
        """Start with no recorded lookups"""
        self.looked_up: list[str] = []

    def lookup(self, ip: str) -> IpLocation:
        """Return a location whose city is the address itself

        Args:
            ip: The address to locate

        Returns:
            A location for that address
        """
        self.looked_up.append(ip)
        return IpLocation(ip=ip, city=f"city-of-{ip}", country="XX")


def attempt(ip: str, username: str, password: str, day: int = 1) -> HoneypotLogLine:
    """Return one login attempt on the given day of August 2025

    Args:
        ip: The attacking address
        username: The username tried
        password: The password tried
        day: The day of the month

    Returns:
        The login attempt
    """
    return HoneypotLogLine(timestamp=datetime(2025, 8, day, 12, 0, 0), ip=ip, username=username, password=password)


@pytest.mark.parametrize(
    ("line", "expected_timestamp"),
    [
        pytest.param(
            "[Mon Aug 11 00:34:57 2025] 203.0.113.9 exampleuser secret\n",
            datetime(2025, 8, 11, 0, 34, 57),
            id="two-digit-day",
        ),
        pytest.param(
            "[Fri May  9 01:02:03 2025] 203.0.113.9 exampleuser secret\n",
            datetime(2025, 5, 9, 1, 2, 3),
            id="space-padded-day",
        ),
    ],
)
def test_parse_reads_timestamp(line: str, expected_timestamp: datetime) -> None:
    """Check that both day paddings the honeypot writes are parsed"""
    parsed = HoneypotLogLine.parse(line)

    assert parsed is not None
    assert parsed.timestamp == expected_timestamp


@pytest.mark.parametrize(
    "line",
    [
        pytest.param("[Mon Aug 11 00:33:53 2025] ssh-honeypot 0.2.0 started on port 22. PID 438795\n", id="startup"),
        pytest.param("[Mon Aug 11 00:35:12 2025] HASSH: 203.0.113.9 45fe0ebe012f sport: 5795 ttl: 64\n", id="hassh"),
        pytest.param("[Mon Aug 11 00:35:12 2025] HASSHServer: 192.0.2.1 45fe0ebe sport: 22 ttl: 64\n", id="server"),
        pytest.param("\n", id="blank"),
    ],
)
def test_parse_ignores_lines_that_are_not_attempts(line: str) -> None:
    """Check that non-attempt lines return None"""
    parsed = HoneypotLogLine.parse(line)

    assert parsed is None


@pytest.mark.parametrize(
    ("line", "expected_password"),
    [
        pytest.param("[Mon Aug 11 16:11:48 2025] 198.51.100.13 root \n", "", id="empty"),
        pytest.param(
            "[Mon Aug 11 00:36:26 2025] 203.0.113.9 exampleuser correct horse battery staple\n",
            "correct horse battery staple",
            id="spaces",
        ),
        pytest.param(
            "[Wed Dec 3 10:00:00 2025] 1.2.3.4 admin ジェリーフィッシュ\n",
            "ジェリーフィッシュ",
            id="unicode",
        ),
    ],
)
def test_parse_keeps_password_verbatim(line: str, expected_password: str) -> None:
    """Check that empty, spaced and non-ascii passwords survive parsing"""
    parsed = HoneypotLogLine.parse(line)

    assert parsed is not None
    assert parsed.password == expected_password


def test_load_returns_attempts_in_file_order(tmp_path: Path) -> None:
    """Check that loading a file keeps attempts in order and skips other lines"""
    log_path = tmp_path / "honeypot.log"
    log_path.write_text(
        "[Mon Aug 11 00:33:53 2025] ssh-honeypot 0.2.0 started on port 22. PID 1\n"
        "[Mon Aug 11 00:34:57 2025] 1.1.1.1 root first\n"
        "[Mon Aug 11 00:35:12 2025] HASSH: 1.1.1.1 abc sport: 1 ttl: 64\n"
        "[Mon Aug 11 00:35:57 2025] 2.2.2.2 admin second\n",
        encoding="utf-8",
    )

    log = HoneypotLog.load(log_path)

    assert [line.password for line in log.lines] == ["first", "second"]


def test_scoreboard_orders_ips_by_attempt_count() -> None:
    """Check that the most active address comes first"""
    log = HoneypotLog(lines=[attempt("1.1.1.1", "root", "a"), *[attempt("2.2.2.2", "root", "b")] * 3])
    cache = IpLocationCache(cache_path=Path("unused"), provider=FakeIpLocationProvider())

    scoreboard = Scoreboard.from_honeypot_log(log, cache)

    assert [(summary.ip, summary.count) for summary in scoreboard.top_ips] == [("2.2.2.2", 3), ("1.1.1.1", 1)]


def test_scoreboard_reports_per_ip_top_usernames_and_passwords() -> None:
    """Check that each address lists its own most common usernames and passwords"""
    log = HoneypotLog(
        lines=[
            attempt("1.1.1.1", "root", "123456"),
            attempt("1.1.1.1", "root", "123456"),
            attempt("1.1.1.1", "admin", "password"),
            attempt("2.2.2.2", "pi", "raspberry"),
        ]
    )
    cache = IpLocationCache(cache_path=Path("unused"), provider=FakeIpLocationProvider())

    scoreboard = Scoreboard.from_honeypot_log(log, cache)

    first = scoreboard.top_ips[0]
    assert first.ip == "1.1.1.1"
    assert [(entry.value, entry.count) for entry in first.top_usernames] == [("root", 2), ("admin", 1)]
    assert [(entry.value, entry.count) for entry in first.top_passwords] == [("123456", 2), ("password", 1)]
    assert first.unique_usernames == 2
    assert first.unique_passwords == 2


def test_scoreboard_locates_only_the_top_ips() -> None:
    """Check that addresses outside the top list are never looked up"""
    log = HoneypotLog(
        lines=[
            *[attempt("1.1.1.1", "root", "a")] * 3,
            *[attempt("2.2.2.2", "root", "a")] * 2,
            attempt("3.3.3.3", "root", "a"),
        ]
    )
    provider = FakeIpLocationProvider()
    cache = IpLocationCache(cache_path=Path("unused"), provider=provider)

    scoreboard = Scoreboard.from_honeypot_log(log, cache, top_ip_count=2)

    assert set(provider.looked_up) == {"1.1.1.1", "2.2.2.2"}
    assert [summary.location.city for summary in scoreboard.top_ips if summary.location] == [
        "city-of-1.1.1.1",
        "city-of-2.2.2.2",
    ]


def test_scoreboard_reports_first_and_last_attempt() -> None:
    """Check that the overall and per-address time ranges are reported"""
    log = HoneypotLog(lines=[attempt("1.1.1.1", "root", "a", day=5), attempt("1.1.1.1", "root", "a", day=2)])
    cache = IpLocationCache(cache_path=Path("unused"), provider=FakeIpLocationProvider())

    scoreboard = Scoreboard.from_honeypot_log(log, cache)

    assert scoreboard.first_attempt == datetime(2025, 8, 2, 12, 0, 0)
    assert scoreboard.last_attempt == datetime(2025, 8, 5, 12, 0, 0)
    assert scoreboard.top_ips[0].first_seen == datetime(2025, 8, 2, 12, 0, 0)
    assert scoreboard.top_ips[0].last_seen == datetime(2025, 8, 5, 12, 0, 0)


def test_scoreboard_handles_empty_log() -> None:
    """Check that an empty log produces an empty scoreboard rather than an error"""
    cache = IpLocationCache(cache_path=Path("unused"), provider=FakeIpLocationProvider())

    scoreboard = Scoreboard.from_honeypot_log(HoneypotLog(), cache)

    assert scoreboard.total_attempts == 0
    assert scoreboard.first_attempt is None
    assert scoreboard.top_ips == []


def test_scoreboard_round_trips_through_json(tmp_path: Path) -> None:
    """Check that the saved file holds the fields the website reads"""
    log = HoneypotLog(lines=[attempt("1.1.1.1", "root", "a")])
    cache = IpLocationCache(cache_path=Path("unused"), provider=FakeIpLocationProvider())
    output_path = tmp_path / "scoreboard.json"

    Scoreboard.from_honeypot_log(log, cache).save(output_path)

    saved = json.loads(output_path.read_text(encoding="utf-8"))
    assert saved["total_attempts"] == 1
    assert saved["top_ips"][0]["location"]["city"] == "city-of-1.1.1.1"
    assert saved["top_ips"][0]["top_passwords"] == [{"value": "a", "count": 1}]
    assert saved["top_usernames"] == [{"value": "root", "count": 1}]


def test_cache_hit_does_not_consult_provider() -> None:
    """Check that a cached address is answered from memory"""
    provider = FakeIpLocationProvider()
    cached = IpLocation(ip="1.1.1.1", city="Cached")
    cache = IpLocationCache(cache_path=Path("unused"), provider=provider, locations={"1.1.1.1": cached})

    location = cache.locate("1.1.1.1")

    assert location.city == "Cached"
    assert provider.looked_up == []


def test_cache_round_trips_through_file(tmp_path: Path) -> None:
    """Check that a saved cache loads back with the same locations"""
    cache_path = tmp_path / "ip-location.cache"
    cache = IpLocationCache(cache_path=cache_path, provider=FakeIpLocationProvider())
    cache.locate("1.1.1.1")
    cache.save()

    reloaded = IpLocationCache.load(cache_path, provider=FakeIpLocationProvider())

    assert reloaded.locations["1.1.1.1"].city == "city-of-1.1.1.1"


def test_cache_load_reads_existing_cache_format(tmp_path: Path) -> None:
    """Check that a cache written by the earlier version of the script still loads"""
    cache_path = tmp_path / "ip-location.cache"
    cache_path.write_text(
        json.dumps(
            {
                "1.1.1.1": {
                    "ip": "1.1.1.1",
                    "city": "Brisbane",
                    "region": "Queensland",
                    "country": "AU",
                    "loc": "-27.4679,153.0281",
                    "timezone": "Australia/Brisbane",
                    "hostname": "one.one.one.one",
                    "org": "AS13335 Cloudflare, Inc.",
                    "postal": "9010",
                    "time_queried": "2026-10-11T22:27:19.150920+00:00",
                }
            }
        ),
        encoding="utf-8",
    )

    cache = IpLocationCache.load(cache_path, provider=FakeIpLocationProvider())

    assert cache.locations["1.1.1.1"].country == "AU"


@responses.activate
def test_ipinfo_lookup_returns_location() -> None:
    """Check that a successful ipinfo.io response becomes a location"""
    responses.get(
        "https://ipinfo.io/1.1.1.1/json",
        json={"ip": "1.1.1.1", "city": "Brisbane", "country": "AU", "loc": "-27.4679,153.0281"},
        status=HTTP_OK,
    )

    location = IpInfoClient().lookup("1.1.1.1")

    assert location.city == "Brisbane"
    assert location.bogon is False


@responses.activate
def test_ipinfo_lookup_accepts_bogon_response() -> None:
    """Check that a reserved address with no location fields is still accepted"""
    responses.get("https://ipinfo.io/10.0.0.1/json", json={"ip": "10.0.0.1", "bogon": True}, status=HTTP_OK)

    location = IpInfoClient().lookup("10.0.0.1")

    assert location.bogon is True
    assert location.city is None


@responses.activate
def test_ipinfo_lookup_raises_on_rate_limit() -> None:
    """Check that a rejected request surfaces as a lookup error"""
    responses.get("https://ipinfo.io/1.1.1.1/json", json={"error": "rate limited"}, status=HTTP_TOO_MANY_REQUESTS)

    with pytest.raises(IpLocationLookupError):
        IpInfoClient().lookup("1.1.1.1")


@responses.activate
def test_ipinfo_lookup_sends_token() -> None:
    """Check that a configured token is sent as a bearer header"""
    responses.get(
        "https://ipinfo.io/1.1.1.1/json",
        json={"ip": "1.1.1.1"},
        status=HTTP_OK,
        match=[responses.matchers.header_matcher({"Authorization": "Bearer secret-token"})],
    )

    location = IpInfoClient(token="secret-token").lookup("1.1.1.1")

    assert location.ip == "1.1.1.1"


def test_main_saves_cache_when_lookup_fails(tmp_path: Path) -> None:
    """Check that a failed run still persists the cache and exits non-zero"""
    log_path = tmp_path / "honeypot.log"
    log_path.write_text("[Mon Aug 11 00:34:57 2025] 1.1.1.1 root first\n", encoding="utf-8")
    cache_path = tmp_path / "ip-location.cache"
    output_path = tmp_path / "scoreboard.json"
    with responses.RequestsMock() as mocked:
        mocked.get("https://ipinfo.io/1.1.1.1/json", status=HTTP_TOO_MANY_REQUESTS)

        exit_code = main(["-i", str(log_path), "-c", str(cache_path), "-o", str(output_path)])

    assert exit_code == 1
    assert cache_path.exists()
    assert not output_path.exists()


def test_main_writes_scoreboard_from_cache(tmp_path: Path) -> None:
    """Check that a fully cached run writes the scoreboard without any network access"""
    log_path = tmp_path / "honeypot.log"
    log_path.write_text("[Mon Aug 11 00:34:57 2025] 1.1.1.1 root first\n", encoding="utf-8")
    cache_path = tmp_path / "ip-location.cache"
    cache_path.write_text(json.dumps({"1.1.1.1": {"ip": "1.1.1.1", "city": "Brisbane"}}), encoding="utf-8")
    output_path = tmp_path / "scoreboard.json"
    with responses.RequestsMock():
        exit_code = main(["-i", str(log_path), "-c", str(cache_path), "-o", str(output_path)])

    assert exit_code == 0
    assert json.loads(output_path.read_text(encoding="utf-8"))["top_ips"][0]["location"]["city"] == "Brisbane"


def test_load_excludes_loopback_attempts(tmp_path: Path) -> None:
    """Check that attempts from 127.0.0.1 are left out of the log"""
    log_path = tmp_path / "honeypot.log"
    log_path.write_text(
        "[Mon Aug 11 00:34:57 2025] 127.0.0.1 root local\n[Mon Aug 11 00:35:57 2025] 203.0.113.9 admin remote\n",
        encoding="utf-8",
    )

    log = HoneypotLog.load(log_path)

    assert [line.ip for line in log.lines] == ["203.0.113.9"]


def test_main_excludes_requested_ips_in_addition_to_loopback(tmp_path: Path) -> None:
    """Check that addresses passed on the command line are excluded alongside 127.0.0.1"""
    log_path = tmp_path / "honeypot.log"
    log_path.write_text(
        "[Mon Aug 11 00:34:57 2025] 127.0.0.1 root local\n"
        "[Mon Aug 11 00:35:57 2025] 203.0.113.9 admin mine\n"
        "[Mon Aug 11 00:36:57 2025] 198.51.100.13 pi remote\n",
        encoding="utf-8",
    )
    cache_path = tmp_path / "ip-location.cache"
    cache_path.write_text(json.dumps({"198.51.100.13": {"ip": "198.51.100.13"}}), encoding="utf-8")
    output_path = tmp_path / "scoreboard.json"
    with responses.RequestsMock():
        exit_code = main(["-i", str(log_path), "-c", str(cache_path), "-o", str(output_path), "-x", "203.0.113.9"])

    assert exit_code == 0
    saved = json.loads(output_path.read_text(encoding="utf-8"))
    assert [entry["ip"] for entry in saved["top_ips"]] == ["198.51.100.13"]
