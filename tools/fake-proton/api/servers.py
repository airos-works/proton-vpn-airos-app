"""A realistic, deterministic list of logical servers for /vpn/v1/logicals.

Field names follow python-proton-vpn-api-core proton/vpn/session/servers/types.py.
Every physical server points at the single fake VPN server: EntryIP is the
configured entry IP (10.0.2.2 by default, the host as seen from a QEMU guest),
Domain is the fake server's TLS name and X25519PublicKey its WireGuard key.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import random

SECURE_CORE, TOR, P2P, STREAMING, IPV6 = 1, 2, 4, 8, 16

# country -> list of (city, state, lat, long, plus servers, free servers)
# plus per-country default features for the Plus servers.
# fmt: off
COUNTRIES = [
    # code  features                     cities
    ("CH", P2P | STREAMING | IPV6, [("Zurich", None, 47.37, 8.54, 5, 0),
                                    ("Geneva", None, 46.20, 6.14, 3, 0)]),
    ("SE", P2P | IPV6,             [("Stockholm", None, 59.33, 18.07, 5, 0)]),
    ("IS", P2P,                    [("Reykjavik", None, 64.15, -21.94, 3, 0)]),
    ("NL", P2P | STREAMING | IPV6, [("Amsterdam", None, 52.37, 4.90, 5, 4)]),
    ("DE", P2P | STREAMING | IPV6, [("Frankfurt", None, 50.11, 8.68, 4, 0),
                                    ("Berlin", None, 52.52, 13.40, 2, 0)]),
    ("JP", STREAMING,              [("Tokyo", None, 35.68, 139.69, 3, 3),
                                    ("Osaka", None, 34.69, 135.50, 2, 0)]),
    ("AU", STREAMING,              [("Sydney", None, -33.87, 151.21, 3, 0),
                                    ("Melbourne", None, -37.81, 144.96, 2, 0),
                                    ("Perth", None, -31.95, 115.86, 1, 0),
                                    ("Brisbane", None, -27.47, 153.03, 1, 0)]),
    ("UK", P2P | STREAMING,        [("London", None, 51.51, -0.13, 4, 0),
                                    ("Manchester", None, 53.48, -2.24, 2, 0)]),
    ("FR", P2P | STREAMING,        [("Paris", None, 48.86, 2.35, 3, 0),
                                    ("Marseille", None, 43.30, 5.37, 1, 0)]),
    ("CA", P2P | STREAMING,        [("Toronto", None, 43.65, -79.38, 3, 2),
                                    ("Montreal", None, 45.50, -73.57, 2, 0),
                                    ("Vancouver", None, 49.28, -123.12, 2, 0)]),
    ("PL", P2P,                    [("Warsaw", None, 52.23, 21.01, 2, 2)]),
    ("RO", P2P,                    [("Bucharest", None, 44.43, 26.10, 2, 2)]),
    ("NO", P2P,                    [("Oslo", None, 59.91, 10.75, 2, 2)]),
    ("MX", 0,                      [("Queretaro", None, 20.59, -100.39, 1, 2)]),
    ("SG", P2P | STREAMING,        [("Singapore", None, 1.35, 103.82, 3, 2)]),
    ("IT", P2P | STREAMING,        [("Milan", None, 45.46, 9.19, 2, 0)]),
    ("ES", P2P | STREAMING,        [("Madrid", None, 40.42, -3.70, 2, 0),
                                    ("Barcelona", None, 41.39, 2.17, 1, 0)]),
    ("AT", P2P,                    [("Vienna", None, 48.21, 16.37, 2, 0)]),
    ("BE", P2P,                    [("Brussels", None, 50.85, 4.35, 2, 0)]),
    ("DK", P2P,                    [("Copenhagen", None, 55.68, 12.57, 2, 0)]),
    ("FI", P2P,                    [("Helsinki", None, 60.17, 24.94, 2, 0)]),
    ("IE", P2P,                    [("Dublin", None, 53.35, -6.26, 1, 0)]),
    ("NZ", STREAMING,              [("Auckland", None, -36.85, 174.76, 2, 0)]),
    ("BR", STREAMING,              [("Sao Paulo", None, -23.55, -46.63, 2, 0)]),
    ("HK", P2P,                    [("Hong Kong", None, 22.32, 114.17, 2, 0)]),
    ("KR", STREAMING,              [("Seoul", None, 37.57, 126.98, 1, 0)]),
    ("ZA", 0,                      [("Johannesburg", None, -26.20, 28.05, 1, 0)]),
    ("PT", P2P,                    [("Lisbon", None, 38.72, -9.14, 3, 0)]),
]

# US servers are named after their state ("US-CA#3") and carry a State.
US_CITIES = [
    # city, state, abbreviation, lat, long, plus servers
    ("New York", "New York", "NY", 40.71, -74.01, 4),
    ("Los Angeles", "California", "CA", 34.05, -118.24, 3),
    ("San Jose", "California", "CA", 37.34, -121.89, 2),
    ("Chicago", "Illinois", "IL", 41.88, -87.63, 3),
    ("Miami", "Florida", "FL", 25.76, -80.19, 2),
    ("Seattle", "Washington", "WA", 47.61, -122.33, 2),
    ("Dallas", "Texas", "TX", 32.78, -96.80, 2),
    ("Atlanta", "Georgia", "GA", 33.75, -84.39, 1),
    ("Denver", "Colorado", "CO", 39.74, -104.99, 1),
    ("Phoenix", "Arizona", "AZ", 33.45, -112.07, 1),
    ("Secaucus", "New Jersey", "NJ", 40.79, -74.06, 1),
]
US_FREE = 4

# Smart routing: the exit country is emulated by servers hosted elsewhere.
SMART_ROUTING = [
    # code, city, lat, long, host country, servers
    ("IN", "Mumbai", 19.08, 72.88, "SG", 2),
    ("TR", "Istanbul", 41.01, 28.98, "RO", 1),
    ("AR", "Buenos Aires", -34.60, -58.38, "US", 1),
]

# Secure Core: entry country -> exit country.
SECURE_CORE_ROUTES = [
    ("CH", "US", 2), ("CH", "UK", 1), ("CH", "DE", 1), ("CH", "JP", 1), ("CH", "AU", 1),
    ("SE", "US", 1), ("SE", "NL", 1), ("SE", "FR", 1),
    ("IS", "UK", 1), ("IS", "CA", 1), ("IS", "AU", 1),
]

# Tor servers: country -> number of "XX#n-TOR" servers.
TOR_SERVERS = {"CH": 2, "SE": 1, "NL": 1}

# Maintenance: whole countries and single logicals (Status 0).
MAINTENANCE_COUNTRIES = {"PT"}
MAINTENANCE_SERVERS = {"DE#4", "US-NY#3"}
# Logical with two physical servers, one of which is down (logical still up).
PARTIAL_DOWN = "SE#2"

# IDs that /vpn/v1/loads returns but /vpn/v1/logicals does not (like the real
# API, which lists a few hidden servers in loads).
HIDDEN_LOAD_ONLY = ["hidden-logical-1", "hidden-logical-2"]
# fmt: on


def _proton_id(seed: str) -> str:
    """88-character base64url id, the shape of real Proton logical/physical IDs."""
    return base64.urlsafe_b64encode(hashlib.sha512(seed.encode()).digest()).decode()


class ExitIpAllocator:
    """Hands out documentation-range (TEST-NET) addresses as fake exit IPs."""

    def __init__(self):
        self._pool = [f"{net}.{host}" for net in ("198.51.100", "203.0.113", "192.0.2")
                      for host in range(10, 250)]
        self._next = 0

    def take(self) -> str:
        ip = self._pool[self._next % len(self._pool)]
        self._next += 1
        return ip


class ServerList:
    def __init__(self, entry_ip: str, domain: str, wg_public_key: str):
        self.entry_ip = entry_ip
        self.domain = domain
        self.wg_public_key = wg_public_key
        self._rng = random.Random(4096)      # deterministic list across restarts
        self._ips = ExitIpAllocator()
        self.base: list[dict] = []           # canonical logicals (without noise)
        self.status_override: dict[str, int] = {}   # name -> Status set via /fake/control
        self._build()

    # -- construction ---------------------------------------------------------
    def _physical(self, name: str, index: int, status: int = 1) -> dict:
        return {
            "ID": _proton_id(f"physical:{name}:{index}"),
            "EntryIP": self.entry_ip,
            "ExitIP": self._ips.take(),
            "Domain": self.domain,
            "Label": "",
            "X25519PublicKey": self.wg_public_key,
            "Generation": 0,
            "Status": status,
            "ServicesDownReason": None,
        }

    def _add(self, name, entry, exit_, city, state, lat, lon, tier, features,
             host_country=None, physicals=1):
        status = 0 if (exit_ in MAINTENANCE_COUNTRIES or name in MAINTENANCE_SERVERS) else 1
        servers = [self._physical(name, i, status) for i in range(physicals)]
        if name == PARTIAL_DOWN:
            servers.append(self._physical(name, physicals, 0))
        self.base.append({
            "ID": _proton_id(f"logical:{name}"),
            "Name": name,
            "EntryCountry": entry,
            "ExitCountry": exit_,
            "Domain": self.domain,
            "Tier": tier,
            "Features": features,
            "Region": None,
            "City": city,
            "State": state,
            "HostCountry": host_country,
            "Score": round(self._rng.uniform(1.0, 4.5), 6),
            "Load": 0 if status == 0 else self._rng.randint(8, 92),
            "Status": status,
            "Location": {"Lat": lat, "Long": lon},
            "Servers": servers,
        })

    def _build(self):
        city_of = {}
        for code, features, cities in COUNTRIES:
            number = 1
            free_number = 1
            for city, state, lat, lon, plus, free in cities:
                city_of.setdefault(code, (city, state, lat, lon))
                for _ in range(plus):
                    extra = IPV6 if (number % 3 == 0 and features & IPV6) else 0
                    feats = (features & ~IPV6) | extra
                    if number % 4 == 0:
                        feats &= ~STREAMING    # not every server streams
                    self._add(f"{code}#{number}", code, code, city, state, lat, lon, 2, feats)
                    number += 1
                for _ in range(free):
                    self._add(f"{code}-FREE#{free_number}", code, code, city, state, lat, lon,
                              0, 0)
                    free_number += 1
            for _ in range(TOR_SERVERS.get(code, 0)):
                city, state, lat, lon = city_of[code]
                self._add(f"{code}#{number}-TOR", code, code, city, state, lat, lon, 2, TOR)
                number += 1

        numbers: dict[str, int] = {}
        for city, state, abbr, lat, lon, plus in US_CITIES:
            city_of.setdefault("US", (city, state, lat, lon))
            for _ in range(plus):
                numbers[abbr] = numbers.get(abbr, 0) + 1
                n = numbers[abbr]
                feats = STREAMING | (P2P if abbr in ("NY", "CA", "IL", "TX") else 0)
                self._add(f"US-{abbr}#{n}", "US", "US", city, state, lat, lon, 2, feats)
        city, state, _, lat, lon, _ = US_CITIES[0]
        for n in range(1, US_FREE + 1):
            self._add(f"US-FREE#{n}", "US", "US", city, state, lat, lon, 0, 0)

        for code, city, lat, lon, host, count in SMART_ROUTING:
            for n in range(1, count + 1):
                self._add(f"{code}#{n}", code, code, city, None, lat, lon, 2, 0,
                          host_country=host)

        sc_numbers: dict[tuple, int] = {}
        for entry, exit_, count in SECURE_CORE_ROUTES:
            city, state, lat, lon = city_of[exit_]
            for _ in range(count):
                sc_numbers[(entry, exit_)] = sc_numbers.get((entry, exit_), 0) + 1
                name = f"{entry}-{exit_}#{sc_numbers[(entry, exit_)]}"
                self._add(name, entry, exit_, city, state, lat, lon, 2, SECURE_CORE | STREAMING)

    # -- views ----------------------------------------------------------------
    def structure_hash(self) -> str:
        """Changes whenever the list changes in a way that warrants a new Last-Modified."""
        data = repr([(s["ID"], s["Name"], self._status(s), self.entry_ip, self.domain,
                      self.wg_public_key) for s in self.base])
        return hashlib.sha256(data.encode()).hexdigest()

    def _status(self, server: dict) -> int:
        return self.status_override.get(server["Name"], server["Status"])

    def logicals(self) -> list[dict]:
        rng = random.Random()
        result = []
        for server in self.base:
            item = copy.deepcopy(server)
            status = self._status(server)
            item["Status"] = status
            for physical in item["Servers"]:
                if status == 0:
                    physical["Status"] = 0
                elif server["Name"] in self.status_override:
                    physical["Status"] = 1
            if server["Name"] == PARTIAL_DOWN and status == 1:
                item["Servers"][-1]["Status"] = 0
            item["Load"] = 0 if status == 0 else max(0, min(100, server["Load"] + rng.randint(-5, 5)))
            item["Score"] = round(max(0.5, server["Score"] + rng.uniform(-0.15, 0.15)), 6)
            result.append(item)
        return result

    def loads(self) -> list[dict]:
        loads = [{"ID": s["ID"], "Load": s["Load"], "Score": s["Score"], "Status": s["Status"]}
                 for s in self.logicals()]
        rng = random.Random()
        for seed in HIDDEN_LOAD_ONLY:
            loads.append({"ID": _proton_id(seed), "Load": rng.randint(10, 60),
                          "Score": round(rng.uniform(1, 4), 6), "Status": 1})
        return loads

    def set_status(self, names=(), countries=(), status=0) -> list[str]:
        changed = []
        for server in self.base:
            if server["Name"] in names or server["ExitCountry"] in countries:
                self.status_override[server["Name"]] = int(status)
                changed.append(server["Name"])
        return changed

    def reset_status(self):
        self.status_override.clear()
