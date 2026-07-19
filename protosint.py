#!/usr/bin/env python3
"""
ProtOSINT - OSINT helper for investigating Proton Mail accounts.
For educational and authorised investigative purposes only.

Modules
  1  Check ONE Proton email (existence + key date)
  2  Enumerate a username across all Proton domains
  3  Check whether a domain uses Proton Mail (MX records + key server)
  4  Batch-verify addresses via a logged-in Proton session (Selenium)
"""

import os
import re
import sys
import json
import time
import getpass
import itertools
import threading
import ipaddress
from datetime import datetime, timezone

import requests

# Enable ANSI colours on Windows 10+ terminals.
if os.name == "nt":
    os.system("")


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

VERSION = "2.0"

# The four public Proton Mail domains. These are NOT universal aliases: which
# ones exist on an account depends on its age and plan (see the Module legend).
PROTON_MAIL_DOMAINS = ["protonmail.com", "protonmail.ch", "pm.me", "proton.me"]

# Domains used by the alias-enumeration module. (passmail.net is a Proton Pass /
# SimpleLogin alias domain, not a Proton Mail mailbox domain - compose accepts
# any address there and the key server has no keys for it, so it can't be
# verified and is deliberately excluded.)
PROTON_ENUM_DOMAINS = list(PROTON_MAIL_DOMAINS)

# Proton's current public key server is mail-api.proton.me; the old
# api.protonmail.ch host still answers for now and is kept as a fallback.
KEY_SERVERS = [
    "https://mail-api.proton.me/pks/lookup",
    "https://api.protonmail.ch/pks/lookup",
]
KEY_SERVER_HOST = "https://mail-api.proton.me/"

# Authenticated account API used by the NeutrOSINT-style existence check.
PROTON_APP_VERSION = "web-account@5.0.153.3"
ACCOUNT_SESSIONS_URL = "https://account.proton.me/api/auth/v4/sessions"
ACCOUNT_COOKIES_URL = "https://account.proton.me/api/core/v4/auth/cookies"
ACCOUNT_AVAILABLE_URL = "https://account.proton.me/api/core/v4/users/available"

REQUEST_TIMEOUT = 20  # seconds - never let a hung socket block forever
USER_AGENT = "Mozilla/5.0 (ProtOSINT; OSINT research tool)"

# Public-IP echo services, tried in order (the rate limit is per IP, so it is
# useful to know which IP Proton sees).
IP_SERVICES = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
    "https://checkip.amazonaws.com",
]

class bcolors:
    OKGREEN = "\033[92m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    ENDC = "\033[0m"


# One reused session: keep-alive + a consistent, non-default User-Agent.
session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})

# Session state


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #

class RateLimitError(Exception):
    """Proton key server returned the 2028 'too many lookups' rate-limit error."""


class ProtonAPIError(Exception):
    """Network failure or any other unexpected/!=2028 API response."""


# --------------------------------------------------------------------------- #
# Loading spinner
# --------------------------------------------------------------------------- #

class Spinner:
    """
    Animated 'working...' indicator shown while a blocking call runs.
    Used as a context manager:  with Spinner("Downloading"): ...
    Falls back to a single static line when stdout is not a TTY (e.g. piped).
    """

    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, message="Working"):
        self.message = message
        self._stop = threading.Event()
        self._thread = None
        self.enabled = sys.stdout.isatty()

    def __enter__(self):
        if self.enabled:
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        else:
            print(f"{self.message}...", flush=True)
        return self

    def _spin(self):
        for frame in itertools.cycle(self.FRAMES):
            if self._stop.is_set():
                break
            sys.stdout.write(
                f"\r{bcolors.OKCYAN}{frame}{bcolors.ENDC} {self.message}... "
            )
            sys.stdout.flush()
            time.sleep(0.08)

    def __exit__(self, *exc):
        self._stop.set()
        if self._thread:
            self._thread.join()
            # Wipe the spinner line so the result prints cleanly.
            sys.stdout.write("\r" + " " * (len(self.message) + 12) + "\r")
            sys.stdout.flush()
        return False  # never suppress exceptions


# --------------------------------------------------------------------------- #
# Low-level API helpers
# --------------------------------------------------------------------------- #

def _parse_proton_error(body):
    """
    If `body` is a Proton JSON error object, return (code, message).
    Valid key-server answers are PGP/HKP text, not JSON, so this only ever
    matches genuine error payloads. Returns (None, None) otherwise.
    """
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None, None
    if isinstance(data, dict) and "Code" in data:
        return data.get("Code"), data.get("Error", "")
    return None, None


def key_server_lookup(op, search):
    """
    Query Proton's public key server (pks/lookup), trying each host in
    KEY_SERVERS until one answers.

      op = "index"  -> existence + key metadata (info:1:N ... pub:...)
      op = "get"    -> full ASCII-armored public key(s)

    Returns the raw response text.
    Raises RateLimitError on the 2028 error, ProtonAPIError on anything else bad.
    """
    last_exc = None
    resp = None
    for base in KEY_SERVERS:
        try:
            resp = session.get(
                base,
                params={"op": op, "search": search},
                timeout=REQUEST_TIMEOUT,
            )
            break
        except requests.exceptions.RequestException as exc:
            last_exc = exc
            continue
    if resp is None:
        raise ProtonAPIError(
            f"network error contacting Proton key server "
            f"({last_exc.__class__.__name__ if last_exc else 'unknown'})"
        )

    body = resp.text
    code, message = _parse_proton_error(body)

    # Rate limit: comes back as JSON, sometimes with HTTP 429, sometimes 200.
    if code == 2028 or resp.status_code == 429:
        raise RateLimitError(message or "Too many recent failed key server lookups")

    # Any other Proton-side JSON error (bad query, temporary block, ...).
    if code is not None:
        raise ProtonAPIError(f"Proton API error {code}: {message}")

    return body


# --------------------------------------------------------------------------- #
# NeutrOSINT-style authenticated existence check
# --------------------------------------------------------------------------- #
# The public key server returns decoy keys for non-existent addresses, so it
# can't reliably confirm existence. Proton's account API (/users/available) can:
# it reports whether a username is still free. This mirrors NeutrOSINT's "light
# mode". It needs a short-lived anonymous auth cookie, built below.
#
# NOTE: this uses Proton's private web API and can change without notice. It is
# also rate-limited separately from the key server (HTTP 429 when exceeded).

_account_session = None  # cached authenticated session (cookie valid ~24h)


def _build_account_session():
    """Create a requests.Session carrying a valid anonymous Proton AUTH cookie."""
    s = requests.Session()
    s.headers.update({
        "User-Agent": USER_AGENT,
        "x-pm-appversion": PROTON_APP_VERSION,
        "x-pm-locale": "en_US",
    })
    # 1) Open an unauthenticated session to obtain tokens.
    r = s.post(ACCOUNT_SESSIONS_URL,
               headers={"x-enforce-unauthsession": "true"},
               timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    tokens = r.json()
    uid = tokens["UID"]
    access = tokens["AccessToken"]
    refresh = tokens["RefreshToken"]
    # 2) Exchange them for AUTH cookies (stored automatically in the jar).
    r = s.post(ACCOUNT_COOKIES_URL,
               headers={"x-pm-uid": uid, "Authorization": f"Bearer {access}"},
               json={"GrantType": "refresh_token", "Persistent": 0,
                     "RedirectURI": "https://protonmail.com", "RefreshToken": refresh,
                     "ResponseType": "token", "State": "C72g4sTNltu4TAL5bUQlnvUT",
                     "UID": uid},
               timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    s.headers.update({"x-pm-uid": uid})
    return s


def _get_account_session(force_new=False):
    global _account_session
    if force_new or _account_session is None:
        _account_session = _build_account_session()
    return _account_session


def neutrosint_check(email):
    """
    Reliable existence check via account.proton.me/users/available.
    Returns (status, detail) where status is one of:
      "exists"       - the address is registered
      "absent"       - the address is free / does not exist
      "rate_limited" - hit the account-API request cap (HTTP 429 / 2028)
      "error"        - auth or network problem (detail explains)
    """
    try:
        s = _get_account_session()
        resp = s.get(ACCOUNT_AVAILABLE_URL,
                     params={"Name": email, "ParseDomain": "1"},
                     timeout=REQUEST_TIMEOUT)
    except requests.exceptions.RequestException as exc:
        return "error", f"auth/network error ({exc.__class__.__name__})"
    except (KeyError, ValueError) as exc:
        return "error", f"unexpected auth response ({exc.__class__.__name__})"

    if resp.status_code == 429:
        return "rate_limited", "HTTP 429 - account API request cap reached"

    # 409 Conflict => the username is taken => the address EXISTS.
    if resp.status_code == 409:
        return "exists", None

    # Some errors arrive as JSON with a Code even on a 2xx.
    try:
        code = resp.json().get("Code")
    except ValueError:
        code = None
    if code == 2028:
        return "rate_limited", "error 2028"

    # 200 => the name is available => the address does NOT exist.
    if resp.status_code == 200:
        return "absent", None

    # An expired cookie can 401; retry once with a fresh session.
    if resp.status_code in (401, 403):
        try:
            s = _get_account_session(force_new=True)
            resp = s.get(ACCOUNT_AVAILABLE_URL,
                         params={"Name": email, "ParseDomain": "1"},
                         timeout=REQUEST_TIMEOUT)
            if resp.status_code == 409:
                return "exists", None
            if resp.status_code == 200:
                return "absent", None
            if resp.status_code == 429:
                return "rate_limited", "HTTP 429"
        except requests.exceptions.RequestException as exc:
            return "error", f"auth retry failed ({exc.__class__.__name__})"

    return "error", f"unexpected HTTP {resp.status_code}"


# --------------------------------------------------------------------------- #
# Custom-domain Proton detection via MX records
# --------------------------------------------------------------------------- #
# For a custom domain, the reliable test (recommended by the NeutrOSINT author)
# is the DNS MX record: if a domain routes mail to Proton, its MX hosts contain
# "protonmail". We resolve MX over DNS-over-HTTPS so no extra dependency or
# system resolver config is needed; dnspython is used as a fallback if present.

DOH_URL = "https://dns.google/resolve"
PROTON_MX_MARKERS = ("protonmail", "proton.me")


def domain_mx(domain):
    """Return a list of MX hostnames for a domain, or None if the lookup failed."""
    try:
        r = session.get(DOH_URL, params={"name": domain, "type": "MX"},
                        headers={"accept": "application/dns-json"},
                        timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            mx = []
            for ans in r.json().get("Answer", []):
                if ans.get("type") == 15:  # MX record
                    parts = ans.get("data", "").split()
                    host = parts[-1].rstrip(".").lower() if parts else ""
                    if host:
                        mx.append(host)
            return mx
    except (requests.exceptions.RequestException, ValueError):
        pass
    # Fallback: dnspython, if the user has it installed.
    try:
        import dns.resolver
        return [str(a.exchange).rstrip(".").lower()
                for a in dns.resolver.resolve(domain, "MX")]
    except Exception:  # noqa: BLE001 - any resolver failure -> unknown
        return None


def domain_uses_proton(domain):
    """(uses, mx_list): uses is True/False, or None if the MX lookup failed."""
    mx = domain_mx(domain)
    if mx is None:
        return None, []
    uses = any(marker in host for host in mx for marker in PROTON_MX_MARKERS)
    return uses, mx



# A machine-readable HKP index line is:
#   pub:<keyid>:<algorithm>:<keylen>:<creationdate>:<expirationdate>:<flags>
# The first pub: record is the primary key. The algorithm field is the OpenPGP
# public-key algorithm number (RFC 4880 / RFC 9580 section 9.1):
#   1 = RSA · 17 = DSA · 18 = ECDH · 19 = ECDSA
#   22 = EdDSA (Ed25519, the modern Proton default) · 25 = X25519 · 27 = Ed25519
PUB_LINE_RE = re.compile(r"^pub:[^:]*:(\d+):(\d*):(\d+):", re.MULTILINE)

# Legend descriptions, keyed by the label parse_key_info produces.
KEY_TYPE_DESC = [
    ("Curve25519", "modern ECC (Ed25519 signing), fastest & most secure - Proton default"),
    ("Ed25519",    "modern ECC signing key, fast & secure"),
    ("X25519",     "modern ECC encryption key"),
    ("RSA 2048",   "older default (pre-2021 accounts), faster"),
    ("RSA 3072",   "RSA, stronger than 2048"),
    ("RSA 4096",   "RSA, strongest & slowest (often imported for legacy compatibility)"),
]


def _algo_label(algo, keylen):
    """Map an OpenPGP algorithm number (+ key length) to a short label."""
    if algo in (1, 2, 3):                     # RSA (any usage flavour)
        return f"RSA {keylen}" if keylen else "RSA"
    return {
        17: "DSA",
        18: "Curve25519",   # ECDH on Curve25519 (encryption)
        19: "ECDSA",
        22: "Curve25519",   # EdDSA/Ed25519 primary - Proton's ECC default
        25: "X25519",
        27: "Ed25519",
    }.get(algo, f"algo {algo}")


def parse_key_info(body):
    """Return (creation_datetime_utc, short_algorithm_label) for the primary key."""
    match = PUB_LINE_RE.search(body)
    if not match:
        return None, None
    algo = int(match.group(1))
    keylen = int(match.group(2)) if match.group(2) else None
    created = int(match.group(3))
    dt = datetime.fromtimestamp(created, tz=timezone.utc)
    return dt, _algo_label(algo, keylen)


def account_status(body):
    """True = valid, False = not valid, None = indeterminate."""
    if "info:1:1" in body:
        return True
    if "info:1:0" in body:
        return False
    match = re.search(r"info:\d+:(\d+)", body)
    if match:
        return int(match.group(1)) > 0
    return None


def parse_key_count(body):
    """Number of keys reported by an index response, or None."""
    match = re.search(r"info:\d+:(\d+)", body)
    return int(match.group(1)) if match else None


# --------------------------------------------------------------------------- #
# Input helpers
# --------------------------------------------------------------------------- #

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(r"^[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def prompt_email(prompt):
    while True:
        value = input(prompt).strip().strip("<>").lower()
        if EMAIL_RE.match(value):
            return value
        print(f"{bcolors.WARNING}Invalid email address, try again.{bcolors.ENDC}")


def prompt_domain(prompt):
    while True:
        value = input(prompt).strip().lower().lstrip("*@")  # accept *@domain / @domain
        if DOMAIN_RE.match(value):
            return value
        print(f"{bcolors.WARNING}Invalid domain, try again.{bcolors.ENDC}")


def ask_yes_no(prompt):
    while True:
        ans = input(f"{prompt} [y/n]: ").strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("Please answer yes or no.")


def print_rate_limit(exc):
    """Human-friendly message for the 2028 rate-limit error."""
    print()
    print(f"{bcolors.FAIL}{bcolors.BOLD}[!] Proton rate-limited this lookup "
          f"(error 2028).{bcolors.ENDC}")
    print(f"{bcolors.FAIL}    \"{exc}\"{bcolors.ENDC}")
    print(f"{bcolors.WARNING}    Wait a while, or run again from a different IP "
          f"(for example a fresh VPN exit), then retry.{bcolors.ENDC}")


# --------------------------------------------------------------------------- #
# Table rendering
# --------------------------------------------------------------------------- #

def _cell(plain, coloured=None):
    """A table cell as (plain_text, coloured_text). Width is measured on plain."""
    return (plain, plain if coloured is None else coloured)


def render_table(headers, rows):
    """
    Render a box-drawing table.
      headers : list[str]
      rows    : list[list[(plain, coloured)]]
    Column widths are computed from the plain text so ANSI colour codes in the
    coloured text do not break alignment.
    """
    widths = [len(h) for h in headers]
    for row in rows:
        for i, (plain, _) in enumerate(row):
            widths[i] = max(widths[i], len(plain))

    def hline(left, mid, right):
        return left + mid.join("─" * (w + 2) for w in widths) + right

    out = [hline("┌", "┬", "┐")]
    out.append("│" + "│".join(f" {h:<{widths[i]}} " for i, h in enumerate(headers)) + "│")
    out.append(hline("├", "┼", "┤"))
    for row in rows:
        cells = []
        for i, (plain, coloured) in enumerate(row):
            pad = widths[i] - len(plain)
            cells.append(f" {coloured}{' ' * pad} ")
        out.append("│" + "│".join(cells) + "│")
    out.append(hline("└", "┴", "┘"))
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Shared verification helpers
# --------------------------------------------------------------------------- #

def keyserver_info(email):
    """(present, date, keytype). Raises RateLimitError / ProtonAPIError."""
    body = key_server_lookup("index", email)
    if account_status(body):
        created, algo = parse_key_info(body)
        return True, created, algo
    return False, None, None


# --------------------------------------------------------------------------- #
# Module 1 - check ONE email: account-API existence + key-server cross-check
# --------------------------------------------------------------------------- #

def check_email():
    print(f"\n{bcolors.BOLD}[1] Check ONE Proton email (reliable){bcolors.ENDC}\n")
    email = prompt_email("Target email (e.g. mikemike@protonmail.com): ")
    _, _, domain = email.partition("@")
    is_proton = domain in PROTON_MAIL_DOMAINS

    # Step 1 - authoritative existence (Selenium if enabled, else account API).
    with Spinner(f"Checking existence ({'Selenium' if SELENIUM_MODE else 'account API'})"):
        status, source = verify_existence(email)

    # Step 2 - key-server cross-check (gives the key date, and exposes decoys).
    key_present = key_date = key_type = None
    key_note = None
    try:
        with Spinner("Cross-checking key server"):
            key_present, key_date, key_type = keyserver_info(email)
    except RateLimitError:
        key_note = "rate-limited (2028)"
    except ProtonAPIError as exc:
        key_note = f"error ({exc})"

    print()
    label = f"Existence ({source})"
    if status == "exists":
        print(f"  {label}: {bcolors.OKGREEN}EXISTS{bcolors.ENDC}")
    elif status == "absent":
        print(f"  {label}: {bcolors.FAIL}DOES NOT EXIST{bcolors.ENDC}")
    elif status == "rate_limited":
        print(f"  {label}: {bcolors.WARNING}rate-limited{bcolors.ENDC}")
    else:
        print(f"  {label}: {bcolors.WARNING}undetermined{bcolors.ENDC}")

    if key_note:
        print(f"  Key server             : {bcolors.DIM}{key_note}{bcolors.ENDC}")
    elif key_present:
        d = f"{key_date:%Y-%m-%d %H:%M UTC}" if key_date else "unknown date"
        if status == "exists":
            # Real key on a confirmed account -> highlight the date (key info).
            shown = f"{bcolors.OKGREEN}{bcolors.BOLD}created {d}  |  {key_type or '—'}"\
                    f"{bcolors.ENDC}"
        elif status == "absent":
            shown = f"{bcolors.FAIL}created {d}  |  {key_type or '—'}  (DECOY){bcolors.ENDC}"
        else:
            shown = f"created {d}  |  {key_type or '—'}"
        print(f"  Key server             : key present, {shown}")
    else:
        print(f"  Key server             : no key returned")

    # Reconcile the two signals.
    if is_proton:
        if status == "absent" and key_present:
            print(f"\n{bcolors.WARNING}  => The key server returned a key WITH a creation "
                  f"date, but {source} says\n     this address does not exist. That "
                  f"key is a DECOY: Proton fabricates keys and\n     dates for non-existent "
                  f"addresses to defeat enumeration. Trust the\n     existence check - this "
                  f"address does NOT exist.{bcolors.ENDC}")
        elif status == "exists" and key_present:
            print(f"\n{bcolors.OKGREEN}  => Confirmed: this address exists, so the key "
                  f"creation date above is genuine\n     (generated by the account owner - "
                  f"not a fabricated decoy).{bcolors.ENDC}")
            print(f"{bcolors.DIM}     Note: this timestamp is when the address's PRIMARY "
                  f"PGP key was created - not\n     necessarily the account itself. If the "
                  f"owner never changed their encryption\n     keys it matches the account "
                  f"creation date; if they regenerated the key later\n     (Settings > "
                  f"Encryption keys), it reflects that newer date instead.{bcolors.ENDC}")
        elif status == "exists" and not key_present and not key_note:
            print(f"\n{bcolors.DIM}  => Exists per the account API; the key server returned "
                  f"no key.{bcolors.ENDC}")
    else:
        # Custom domain: the account API can't check individual addresses, so use
        # the domain's MX records to decide whether it's a Proton domain at all.
        with Spinner(f"Checking {domain} MX records"):
            uses, mx = domain_uses_proton(domain)
        print()
        if mx:
            print(f"  Domain MX              : {', '.join(mx)}")
        if uses is True:
            print(f"  {bcolors.OKGREEN}{bcolors.BOLD}=> Connected to Proton: YES{bcolors.ENDC}"
                  f" - {domain} routes mail through Proton, so this")
            print(f"     is a Proton-hosted address. Whether this exact mailbox exists can't "
                  f"be\n     confirmed from public data (it may be a catch-all); use module 5 "
                  f"for that.")
        elif uses is False:
            print(f"  {bcolors.FAIL}{bcolors.BOLD}=> Connected to Proton: NO{bcolors.ENDC}"
                  f" - {domain} does not route mail through Proton.")
            print(f"     The key the key server returned is not a real Proton account key.")
        else:
            print(f"  {bcolors.WARNING}=> Could not resolve {domain}'s MX records, so Proton "
                  f"usage is unconfirmed.{bcolors.ENDC}")

    if status == "rate_limited":
        print(f"{bcolors.WARNING}  Proton rate-limited this lookup. Wait a while or try "
              f"from a different IP.{bcolors.ENDC}")

    if status == "exists" and key_present and ask_yes_no("\nDownload the public key?"):
        download_public_key(email)


# --------------------------------------------------------------------------- #
# Module 2 - enumerate a username across all Proton domains (account API)
# --------------------------------------------------------------------------- #

def enumerate_aliases():
    print(f"\n{bcolors.BOLD}[2] Enumerate a username across all Proton domains"
          f"{bcolors.ENDC}\n")
    raw = input("Username or email (e.g. mikemike or mikemike@proton.me): ").strip().lower()
    local_part = raw.split("@")[0]
    if not local_part or not re.match(r"^[a-z0-9._%+\-]+$", local_part):
        print(f"{bcolors.WARNING}Invalid username.{bcolors.ENDC}")
        return

    candidates = [f"{local_part}@{d}" for d in PROTON_ENUM_DOMAINS]
    selenium = SELENIUM_MODE and ensure_selenium_alive()
    method = "Selenium (live Proton session)" if selenium else "the account API"
    print(f"\nTesting '{local_part}' on {len(candidates)} Proton domains using {method}.")
    print(f"{bcolors.DIM}This avoids decoy-key false positives. Key dates are fetched only "
          f"for addresses that exist.{bcolors.ENDC}\n")

    # Get an existence verdict per candidate.
    verdicts = {}        # email -> exists/absent/unknown/rate_limited
    rate_note = None
    if selenium:
        # One compose window, all addresses at once - reliable and avoids stacking.
        try:
            with Spinner(f"Checking {len(candidates)} domains in one compose window"):
                sel = selenium_check_emails(candidates)
        except Exception as exc:  # noqa: BLE001
            print(f"{bcolors.WARNING}Selenium problem: {exc}{bcolors.ENDC}")
            sel = {}
        for cand in candidates:
            r = sel.get(cand)
            verdicts[cand] = "exists" if r is True else "absent" if r is False else "unknown"
    else:
        for i, cand in enumerate(candidates, 1):
            with Spinner(f"[{i}/{len(candidates)}] {cand}"):
                status, detail = verify_existence(cand)
            verdicts[cand] = status
            if status == "rate_limited":
                rate_note = detail
                break

    rows = []            # (rank, addr, exists_plain, exists_col, date, keytype)
    existing = []
    for cand in candidates:
        status = verdicts.get(cand)
        if status == "exists":
            date_str, ktype = "—", "—"
            try:
                present, d, algo = keyserver_info(cand)
                if present and d:
                    date_str, ktype = f"{d:%Y-%m-%d %H:%M}", (algo or "—")
            except (RateLimitError, ProtonAPIError):
                date_str, ktype = "?", "?"
            rows.append((0, cand, "yes", f"{bcolors.OKGREEN}yes{bcolors.ENDC}",
                         date_str, ktype))
            existing.append(cand)
        elif status == "absent":
            rows.append((1, cand, "no", f"{bcolors.FAIL}no{bcolors.ENDC}", "—", "—"))
        elif status == "rate_limited":
            rows.append((2, cand, "rate-limited",
                         f"{bcolors.WARNING}rate-limited{bcolors.ENDC}", "—", "—"))
        else:
            rows.append((3, cand, "no (suspected)",
                         f"{bcolors.WARNING}no (suspected){bcolors.ENDC}", "—", "—"))

    rows.sort(key=lambda r: (r[0], r[1]))
    print()
    header_src = "Selenium" if selenium else "API"
    print(render_table(
        ["Address", f"Exists ({header_src})", "Key created (UTC)", "Key type"],
        [[_cell(a), _cell(sp, sc), _cell(dt), _cell(kt)]
         for _r, a, sp, sc, dt, kt in rows]
    ))
    print_enum_legend(selenium)

    if rate_note:
        print(f"{bcolors.WARNING}Proton rate-limited the lookups ({rate_note}); the list "
              f"above may be incomplete. Wait or use another IP.{bcolors.ENDC}")

    if existing and ask_yes_no(
            "\nDownload the public key for one of the existing addresses?"):
        target = existing[0] if len(existing) == 1 else _pick_from_list(existing)
        download_public_key(target)


def print_enum_legend(selenium=False):
    """Legend for the enumeration table."""
    algos = " · ".join(f"{label} = {desc}" for label, desc in KEY_TYPE_DESC)
    source = ("Proton's compose validation (Selenium)" if selenium
              else "Proton's account API")
    print(f"\n{bcolors.DIM}Legend")
    print(f"  Exists    yes = registered · no = free/not registered · "
          f"no (suspected) = couldn't confirm (treat as probably not).")
    print(f"            Verdicts come from {source}, not the key server, so decoy "
          f"keys can't cause false positives.")
    print(f"  Key type  {algos}")
    print(f"  Domains   Proton's domains are NOT universal aliases: @protonmail.ch is "
          f"pre-2016 only, @pm.me needs a paid plan, @proton.me was optional before "
          f"mid-2022. A 'no' just means that address isn't set up.{bcolors.ENDC}")


def _pick_from_list(items):
    while True:
        raw = input(f"Choose 1-{len(items)}: ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(items):
            return items[int(raw) - 1]
        print("Invalid choice.")


def download_public_key(email):
    try:
        with Spinner(f"Fetching public key for {email}"):
            body = key_server_lookup("get", email)
    except RateLimitError as exc:
        print_rate_limit(exc)
        return
    except ProtonAPIError as exc:
        print(f"{bcolors.WARNING}Could not fetch key: {exc}{bcolors.ENDC}")
        return
    print("\n" + body.strip())


# --------------------------------------------------------------------------- #
# Module 3 - does a domain use Proton Mail? (via MX records)
# --------------------------------------------------------------------------- #

def check_domain_wildcard():
    print(f"\n{bcolors.BOLD}[3] Does a domain use Proton Mail?{bcolors.ENDC}\n")
    domain = prompt_domain("Domain to check (e.g. proton.me): ")

    # Method 1 - MX records (most reliable for a custom domain).
    with Spinner(f"Looking up MX records for {domain}"):
        mx_uses, mx = domain_uses_proton(domain)

    # Method 2 - key-server wildcard *@domain (cross-check; can be blank/decoy).
    ks_uses = None
    ks_note = None
    try:
        with Spinner(f"Querying key server for *@{domain}"):
            body = key_server_lookup("index", f"*@{domain}")
        count = parse_key_count(body)
        ks_uses = (count is not None and count > 0)
        if count is None:
            ks_note = "response not understood"
    except RateLimitError as exc:
        ks_note = f"rate-limited ({exc})"
    except ProtonAPIError as exc:
        ks_note = f"error ({exc})"

    print()
    print(f"{bcolors.BOLD}Method 1 - MX records:{bcolors.ENDC}")
    if mx_uses is None:
        print(f"  {bcolors.WARNING}Could not resolve MX records for {domain}.{bcolors.ENDC}")
    elif not mx:
        print(f"  {domain} has {bcolors.FAIL}no MX records{bcolors.ENDC} "
              f"(no mail server configured).")
    else:
        print(f"  MX records: {', '.join(mx)}")
        if mx_uses:
            print(f"  {bcolors.OKGREEN}{bcolors.BOLD}=> USES Proton Mail{bcolors.ENDC} "
                  f"(MX points to Proton's servers).")
        else:
            print(f"  {bcolors.FAIL}{bcolors.BOLD}=> does NOT use Proton Mail{bcolors.ENDC} "
                  f"(mail is handled elsewhere).")

    print(f"\n{bcolors.BOLD}Method 2 - key-server wildcard (*@{domain}):{bcolors.ENDC}")
    if ks_note:
        print(f"  {bcolors.WARNING}{ks_note}{bcolors.ENDC}")
    elif ks_uses:
        print(f"  {bcolors.OKGREEN}Found published key(s){bcolors.ENDC} for this domain on "
              f"the key server.")
    else:
        print(f"  {bcolors.FAIL}No published keys{bcolors.ENDC} found for this domain on "
              f"the key server.")

    print()
    if mx_uses is not None and ks_note is None:
        if mx_uses == ks_uses:
            colour = bcolors.OKGREEN if mx_uses else bcolors.FAIL
            verb = "uses" if mx_uses else "does not use"
            print(f"{colour}Both methods agree: {domain} {verb} Proton Mail."
                  f"{bcolors.ENDC}")
        else:
            print(f"{bcolors.WARNING}The two methods disagree - trust the MX record result "
                  f"(Method 1); the key server\ncan be empty even for a real Proton domain "
                  f"if no address has published a key yet.{bcolors.ENDC}")
    print(f"{bcolors.DIM}MX records are the definitive signal: they show where the domain's "
          f"mail is actually\nrouted. The key server only shows whether at least one address "
          f"has published a PGP key,\nwhich can miss domains that exist but haven't sent "
          f"encrypted mail yet.{bcolors.ENDC}")


# --------------------------------------------------------------------------- #
# Startup banner
# --------------------------------------------------------------------------- #

BOX_W = 58  # inner width of the info panel


def _box_top(title=""):
    if title:
        head = f"─ {title} "
        return "╭" + head + "─" * (BOX_W - len(head)) + "╮"
    return "╭" + "─" * BOX_W + "╮"


def _box_bottom():
    return "╰" + "─" * BOX_W + "╯"


def _box_row(label, value_plain, value_coloured=None):
    value_coloured = value_plain if value_coloured is None else value_coloured
    left = f"  {label:<14}: "
    pad = max(BOX_W - len(left) - len(value_plain), 0)
    return f"│{left}{value_coloured}{' ' * pad}│"


def _status(ok):
    text = "ONLINE" if ok else "OFFLINE"
    colour = bcolors.OKGREEN if ok else bcolors.FAIL
    return text, f"{colour}{text}{bcolors.ENDC}"


def get_public_ip():
    for url in IP_SERVICES:
        try:
            resp = session.get(url, timeout=8)
            if resp.status_code == 200:
                ip = resp.text.strip()
                ipaddress.ip_address(ip)  # validate
                return ip
        except (requests.exceptions.RequestException, ValueError):
            continue
    return None


def _key_server_online():
    # HEAD the host root (not a pks lookup) so the status check does not
    # consume a key-server lookup from the hourly budget.
    try:
        resp = session.head(KEY_SERVER_HOST, timeout=REQUEST_TIMEOUT)
        return resp.status_code < 500
    except requests.exceptions.RequestException:
        return False


def print_ascii():
    print(bcolors.OKCYAN + r"""
  ____            _    ___  ____ ___ _   _ _____
 |  _ \ _ __ ___ | |_ / _ \/ ___|_ _| \ | |_   _|
 | |_) | '__/ _ \| __| | | \___ \| ||  \| | | |
 |  __/| | | (_) | |_| |_| |___) | || |\  | | |
 |_|   |_|  \___/ \__|\___/|____/___|_| \_| |_|
""" + bcolors.ENDC)


def startup_banner():
    print_ascii()
    print(f"  {bcolors.BOLD}ProtOSINT v{VERSION}{bcolors.ENDC}"
          f"{bcolors.DIM} - Proton Mail OSINT toolkit{bcolors.ENDC}\n")

    with Spinner("Gathering session info"):
        public_ip = get_public_ip()
        key_ok = _key_server_online()

    ip_plain = public_ip or "unavailable"
    ip_colour = ((bcolors.OKGREEN if public_ip else bcolors.WARNING)
                 + ip_plain + bcolors.ENDC)
    key_plain, key_coloured = _status(key_ok)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    print(_box_top("Session"))
    print(_box_row("Your public IP", ip_plain, ip_colour))
    print(_box_row("Key server", key_plain, key_coloured))
    print(_box_row("Time", now))
    print(_box_bottom())

    print(f"""
{bcolors.WARNING}{bcolors.BOLD}⚠  Disclaimer{bcolors.ENDC}
{bcolors.WARNING}   Proton rate-limits these lookups. If you hit a limit, wait a while or run
   again from a different IP. Your public IP is shown above so you know which
   address is subject to the limit.
   Use only for authorised, educational OSINT - you are responsible for how
   you use this tool.{bcolors.ENDC}""")


# --------------------------------------------------------------------------- #
# Module 4 - batch-verify addresses via a logged-in Proton session (Selenium)
# --------------------------------------------------------------------------- #
# The account API checks whether a *username* is free, which is not the same as
# whether a specific address is deliverable - e.g. test@protonmail.ch can look
# "taken" while the .ch address itself doesn't exist. The only fully reliable
# check is the one Proton's own compose window does: type the address into the
# "To" field and see whether it's accepted or flagged "address doesn't exist".
# This module automates exactly that with Selenium, using credentials from
# config.json. (Same approach as NeutrOSINT's selenium mode.)

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

# Global Selenium session (built at startup when enabled in config).
_driver = None
SELENIUM_MODE = False
HEADLESS = False
_proton_creds = None      # (username, password) cached so we can relaunch silently

DEFAULT_CONFIG = {
    "_comment": (
        "use_selenium: log into Proton and verify with its own compose check "
        "(most reliable). headless: hide the browser window - only use it on an "
        "account WITHOUT 2FA/CAPTCHA. Leave password blank to be asked at runtime "
        "(safer - it is then never written to disk)."
    ),
    "proton": {"username": "", "password": ""},
    "settings": {"use_selenium": True, "headless": True},
}


def ensure_config():
    """Create a template config.json next to the script if none exists."""
    if not os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "w") as fh:
                json.dump(DEFAULT_CONFIG, fh, indent=2)
                fh.write("\n")
        except OSError:
            pass


def _load_config():
    """Read config.json, returning {} if it's missing or malformed."""
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
        except (OSError, ValueError):
            pass
    return {}


def _as_bool(value, default=True):
    """Accept real JSON booleans, or strings like 'yes'/'true'/'1'."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("yes", "true", "1", "on")
    return default


def get_use_selenium():
    settings = _load_config().get("settings", {})
    return _as_bool(settings.get("use_selenium", True), default=True)


def get_headless():
    settings = _load_config().get("settings", {})
    return _as_bool(settings.get("headless", True), default=True)


def load_proton_credentials():
    proton = _load_config().get("proton", {})
    username = str(proton.get("username", "") or "").strip()
    password = str(proton.get("password", "") or "").strip()
    if not username:
        username = input("Proton username / email: ").strip()
    if not password:
        password = getpass.getpass("Proton password (hidden, not stored): ")
    return username, password


# --------------------------------------------------------------------------- #
# Selenium session management
# --------------------------------------------------------------------------- #

def _build_driver():
    """Start Chrome (or Firefox) with flags that work even when run as root."""
    from selenium import webdriver
    try:
        from selenium.webdriver.chrome.options import Options as ChromeOptions
        opts = ChromeOptions()
        # --no-sandbox is REQUIRED when running as root (e.g. Kali); without it
        # Chrome dies with "target window already closed / web view not found".
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--start-maximized")
        if HEADLESS:
            opts.add_argument("--headless=new")
            opts.add_argument("--window-size=1920,1080")
        return webdriver.Chrome(options=opts)
    except Exception:
        from selenium.webdriver.firefox.options import Options as FoxOptions
        fopts = FoxOptions()
        if HEADLESS:
            fopts.add_argument("-headless")
        return webdriver.Firefox(options=fopts)


def selenium_login(username, password):
    """Launch a browser and log into Proton. Returns a driver at the mailbox."""
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import NoSuchElementException

    driver = _build_driver()
    wait = WebDriverWait(driver, 120)
    driver.get("https://account.proton.me/login")

    user_box = wait.until(EC.presence_of_element_located((By.ID, "username")))
    user_box.clear()
    user_box.send_keys(username)

    # Proton usually shows both fields; if not, submit to reveal the password step.
    try:
        pw_box = driver.find_element(By.ID, "password")
    except NoSuchElementException:
        driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        pw_box = wait.until(EC.presence_of_element_located((By.ID, "password")))
    pw_box.clear()
    pw_box.send_keys(password)
    try:
        driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
    except NoSuchElementException:
        pw_box.send_keys(Keys.RETURN)

    # Wait for authentication to complete. Proton often lands on the app picker
    # (account.proton.me/apps) rather than Mail. The long timeout lets the user
    # solve any 2FA / CAPTCHA in the window.
    print(f"{bcolors.DIM}   Waiting for login (solve any 2FA/CAPTCHA in the browser "
          f"window)...{bcolors.ENDC}")
    wait.until(lambda d: (
        "/apps" in d.current_url
        or "mail.proton.me" in d.current_url
        or d.find_elements(By.CSS_SELECTOR, '[data-testid="sidebar:compose"]')
    ))

    # Go straight to the webmail. The bare URL redirects to the correct /u/N
    # inbox for this session, so we don't need to guess the account index.
    if "mail.proton.me" not in driver.current_url:
        driver.get("https://mail.proton.me/")

    # Wait for the mailbox to be ready (the compose button lives in the sidebar).
    WebDriverWait(driver, 90).until(EC.presence_of_element_located(
        (By.CSS_SELECTOR, '[data-testid="sidebar:compose"]')))
    return driver


def selenium_check_emails(emails):
    """
    Check addresses through Proton's compose recipient validation using the live
    session. Returns {email: True/False/None}. None = couldn't read.
    """
    global _driver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC

    results = {e: None for e in emails}
    if _driver is None:
        return results
    wait = WebDriverWait(_driver, 30)

    # Make sure we're in the webmail, then open a fresh composer.
    if "mail.proton.me" not in _driver.current_url:
        _driver.get("https://mail.proton.me/")
    compose_btn = wait.until(EC.element_to_be_clickable(
        (By.CSS_SELECTOR, '[data-testid="sidebar:compose"]')))
    compose_btn.click()
    to_field = wait.until(EC.presence_of_element_located(
        (By.CSS_SELECTOR, 'input[data-testid="composer:to"]')))
    for addr in emails:
        to_field.send_keys(addr)
        to_field.send_keys(Keys.ENTER)
        time.sleep(1.0)
    time.sleep(3.0)  # let Proton validate

    wanted = {e.strip().lower() for e in emails}
    items = _driver.find_elements(
        By.XPATH,
        "//div[@data-testid='composer:to-field']"
        "//div[contains(@class,'composer-addresses-item')]")
    for item in items:
        try:
            label = item.find_element(
                By.XPATH, ".//span[@data-testid='composer-addresses-item-label']"
            ).text.strip().lower()
        except Exception:  # noqa: BLE001
            label = item.text.strip().lower()
        blob = ((item.get_attribute("class") or "") +
                (item.get_attribute("outerHTML") or "")).lower()
        # A non-existent recipient is flagged invalid (red/orange chip, error icon).
        invalid = any(k in blob for k in ("invalid", "not exist", "doesn't exist",
                                          "error", "warning"))
        # Match the chip back to one of the requested addresses (labels can carry
        # extra text, so fall back to a substring match).
        match = None
        if label in wanted:
            match = label
        else:
            for e in wanted:
                if e and e in label:
                    match = e
                    break
        if match:
            results[match] = not invalid

    # Best-effort: discard the composer so chips don't pile up.
    try:
        _driver.find_element(
            By.CSS_SELECTOR, '[data-testid="composer:close-button"]').click()
        time.sleep(0.5)
        for sel in ('[data-testid="discard-draft:discard"]',
                    'button[data-testid="modal:confirm"]'):
            try:
                _driver.find_element(By.CSS_SELECTOR, sel).click()
                break
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        pass
    return results


def _selenium_disclaimer():
    if HEADLESS:
        print(f"{bcolors.DIM}   (Running the browser headless / in the background.)"
              f"{bcolors.ENDC}")
    else:
        print(f"{bcolors.WARNING}{bcolors.BOLD}   A Proton browser window will open. Leave "
              f"it open and DON'T click inside it -{bcolors.ENDC}")
        print(f"{bcolors.WARNING}   switch back to THIS terminal to choose a module. "
              f"(Set headless = yes in{bcolors.ENDC}")
        print(f"{bcolors.WARNING}   config.json to hide the window - only on accounts "
              f"without 2FA/CAPTCHA.){bcolors.ENDC}")


def init_selenium():
    """Start the shared Selenium session if enabled. Sets SELENIUM_MODE/_driver."""
    global _driver, SELENIUM_MODE, HEADLESS, _proton_creds
    if not get_use_selenium():
        return
    try:
        import selenium  # noqa: F401
    except ImportError:
        print(f"{bcolors.WARNING}config.json has use_selenium=true but Selenium isn't "
              f"installed.\nInstall it (pip install selenium) or set use_selenium=false. "
              f"Falling back to the account API for now.{bcolors.ENDC}")
        return
    HEADLESS = get_headless()
    print(f"{bcolors.BOLD}Selenium verification is ON.{bcolors.ENDC}")
    _selenium_disclaimer()
    _proton_creds = load_proton_credentials()
    username, password = _proton_creds
    if not username or not password:
        print(f"{bcolors.WARNING}Missing credentials; falling back to the account API."
              f"{bcolors.ENDC}")
        return
    try:
        with Spinner("Logging into Proton"):
            _driver = selenium_login(username, password)
        SELENIUM_MODE = True
        print(f"{bcolors.OKGREEN}Logged in - modules 1, 2 and 4 will verify via the live "
              f"Proton session.{bcolors.ENDC}")
    except Exception as exc:  # noqa: BLE001
        print(f"{bcolors.FAIL}Selenium login failed: {exc}{bcolors.ENDC}")
        print(f"{bcolors.DIM}Falling back to the account API. On Kali/root the browser "
              f"needs --no-sandbox (already set); if it still fails, Proton's login page "
              f"may have changed.{bcolors.ENDC}")
        try:
            if _driver:
                _driver.quit()
        except Exception:  # noqa: BLE001
            pass
        _driver = None


def _driver_alive():
    """True if the browser session is still usable."""
    if _driver is None:
        return False
    try:
        _ = _driver.current_url        # cheap call that fails on a dead session
        return True
    except Exception:  # noqa: BLE001
        return False


def ensure_selenium_alive():
    """
    Make sure a live Selenium session exists, relaunching it if the browser was
    closed. Returns True if a session is ready, False otherwise.
    """
    global _driver, SELENIUM_MODE, _proton_creds
    if _driver_alive():
        return True

    print(f"{bcolors.WARNING}The Proton browser session is closed - reopening it..."
          f"{bcolors.ENDC}")
    if _proton_creds is None:
        _proton_creds = load_proton_credentials()
    username, password = _proton_creds
    if not username or not password:
        print(f"{bcolors.WARNING}No credentials available to relaunch.{bcolors.ENDC}")
        return False
    _selenium_disclaimer()
    try:
        with Spinner("Reconnecting to Proton"):
            _driver = selenium_login(username, password)
        SELENIUM_MODE = True
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"{bcolors.FAIL}Could not reopen the session: {exc}{bcolors.ENDC}")
        _driver = None
        return False


def close_selenium():
    global _driver
    if _driver is not None:
        try:
            _driver.quit()
        except Exception:  # noqa: BLE001
            pass
        _driver = None


def verify_existence(email):
    """
    Authoritative existence check, honouring the Selenium setting.
    Returns (status, source) with status in exists/absent/unknown/rate_limited/error.
    """
    if SELENIUM_MODE:
        if ensure_selenium_alive():
            try:
                r = selenium_check_emails([email]).get(email)
            except Exception as exc:  # noqa: BLE001
                return "unknown", f"Selenium error ({exc.__class__.__name__})"
            if r is True:
                return "exists", "Selenium (compose)"
            if r is False:
                return "absent", "Selenium (compose)"
            return "unknown", "Selenium (couldn't read)"
        status, detail = neutrosint_check(email)
        return status, "account API (Selenium unavailable)"
    status, detail = neutrosint_check(email)
    src = "account API" if status in ("exists", "absent") else f"account API: {detail}"
    return status, src





def batch_verify_selenium():
    """Module 4: check a list of addresses through the live Proton session."""
    print(f"\n{bcolors.BOLD}[4] Batch-verify addresses via the live Proton session"
          f"{bcolors.ENDC}\n")
    if not SELENIUM_MODE:
        print(f"{bcolors.WARNING}Selenium verification is off. Set "
              f"use_selenium to true\nin config.json and restart to use this module."
              f"{bcolors.ENDC}")
        return
    if not ensure_selenium_alive():
        print(f"{bcolors.FAIL}Couldn't open a Proton session.{bcolors.ENDC}")
        return

    print("Addresses to verify (one per line, blank line to finish):")
    targets = []
    while True:
        a = input("  address> ").strip().lower()
        if not a:
            break
        if EMAIL_RE.match(a):
            targets.append(a)
        else:
            print(f"    {bcolors.WARNING}invalid, skipped{bcolors.ENDC}")
    if not targets:
        print("Nothing to check.")
        return

    try:
        with Spinner(f"Checking {len(targets)} address(es) via compose"):
            results = selenium_check_emails(targets)
    except Exception as exc:  # noqa: BLE001
        print(f"{bcolors.WARNING}Selenium hit a problem: {exc}{bcolors.ENDC}")
        print(f"{bcolors.DIM}Proton's page may have changed; adjust the selectors near "
              f"selenium_check_emails().{bcolors.ENDC}")
        return

    print()
    for addr in targets:
        ok = results.get(addr)
        if ok is True:
            info = ""
            try:
                present, d, algo = keyserver_info(addr)
                if present and d:
                    info = (f"  |  created {bcolors.OKGREEN}{d:%Y-%m-%d %H:%M UTC}"
                            f"{bcolors.ENDC}  |  {algo or '—'}")
            except (RateLimitError, ProtonAPIError):
                pass
            print(f"  {addr}: {bcolors.OKGREEN}EXISTS{bcolors.ENDC}{info}")
        elif ok is False:
            print(f"  {addr}: {bcolors.FAIL}DOES NOT EXIST{bcolors.ENDC}")
        else:
            print(f"  {addr}: {bcolors.WARNING}could not read result{bcolors.ENDC}")


def print_menu():
    print(f"""
{bcolors.BOLD}Choose a module:{bcolors.ENDC}
  {bcolors.OKCYAN}1{bcolors.ENDC} - Check ONE Proton email (reliable: existence + key date)
  {bcolors.OKCYAN}2{bcolors.ENDC} - Enumerate a username across all Proton domains
  {bcolors.OKCYAN}3{bcolors.ENDC} - Check whether a domain uses Proton Mail (MX + key server)
  {bcolors.OKCYAN}4{bcolors.ENDC} - Batch-verify addresses via the live Proton session"""
          + (f"" if SELENIUM_MODE else f" {bcolors.DIM}(needs use_selenium=true){bcolors.ENDC}")
          + f"""
  {bcolors.OKCYAN}q{bcolors.ENDC} - Quit""")


def main():
    ensure_config()
    try:
        startup_banner()
        init_selenium()  # logs in now if use_selenium is true in config.json
        while True:
            print_menu()
            choice = input("> ").strip().lower()
            if choice == "1":
                check_email()
            elif choice == "2":
                enumerate_aliases()
            elif choice == "3":
                check_domain_wildcard()
            elif choice == "4":
                batch_verify_selenium()
            elif choice in ("q", "quit", "exit"):
                break
            else:
                print(f"{bcolors.WARNING}Unknown choice.{bcolors.ENDC}")
    except (EOFError, KeyboardInterrupt):
        print("\nBye.")
    finally:
        close_selenium()
        sys.exit(0)


if __name__ == "__main__":
    main()
