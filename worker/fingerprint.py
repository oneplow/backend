"""
Realistic browser fingerprint rotation. Each call to fingerprint() returns
a coherent (UA, headers, email-style) set so every signup looks like a
different person on a different machine.
"""
import random
import string

# --- Chrome versions (recent stable releases) --------------------------------
_CHROME_VERSIONS = [
    "144.0.0.0", "143.0.6917.183", "143.0.6917.160",
    "142.0.6926.80", "142.0.6926.60", "141.0.6953.120",
    "140.0.6099.130", "139.0.6945.88", "138.0.6920.100",
]

_WIN_VERSIONS = [
    "Windows NT 10.0; Win64; x64",
    "Windows NT 11.0; Win64; x64",
]

_MAC_VERSIONS = [
    "Macintosh; Intel Mac OS X 10_15_7",
    "Macintosh; Intel Mac OS X 14_5",
    "Macintosh; Intel Mac OS X 14_4_1",
    "Macintosh; Intel Mac OS X 13_6_7",
]

_LINUX_VERSIONS = [
    "X11; Linux x86_64",
    "X11; Ubuntu; Linux x86_64",
]

_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,th;q=0.8",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,ja;q=0.8",
    "en,en-US;q=0.9",
    "en-US,en;q=0.8",
]

_SEC_CH_PLATFORMS = {
    "Windows NT": '"Windows"',
    "Macintosh": '"macOS"',
    "X11": '"Linux"',
}

# --- Realistic email patterns -------------------------------------------------
_FIRST_NAMES = [
    "alex", "chris", "jordan", "taylor", "morgan", "casey", "riley",
    "quinn", "avery", "blake", "drew", "sam", "pat", "jamie", "lee",
    "max", "sky", "sage", "kai", "river", "logan", "mason", "carter",
    "noah", "emma", "liam", "mia", "ella", "jack", "sofia", "oliver",
    "lucas", "henry", "daniel", "michael", "david", "james", "william",
]

_LAST_NAMES = [
    "smith", "johnson", "brown", "davis", "miller", "wilson", "moore",
    "taylor", "anderson", "thomas", "jackson", "white", "harris",
    "martin", "garcia", "clark", "lewis", "lee", "walker", "hall",
    "young", "king", "wright", "green", "baker", "adams", "nelson",
]

_EMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "protonmail.com", "icloud.com", "mail.com", "zoho.com",
    "aol.com", "live.com", "yandex.com", "fastmail.com",
]

_SEPARATORS = [".", "_", ""]


def _gen_realistic_email() -> str:
    """Generate an email that looks like a real person signed up.
    Patterns: firstname.lastname99@gmail.com, firstlast_2024@outlook.com, etc.
    """
    style = random.choice(["first_last", "first_last_num", "first_initial", "nickname"])
    first = random.choice(_FIRST_NAMES)
    last = random.choice(_LAST_NAMES)
    sep = random.choice(_SEPARATORS)
    domain = random.choice(_EMAIL_DOMAINS)

    if style == "first_last":
        local = f"{first}{sep}{last}"
    elif style == "first_last_num":
        num = random.choice([
            str(random.randint(1, 99)),
            str(random.randint(1990, 2006)),
        ])
        local = f"{first}{sep}{last}{num}"
    elif style == "first_initial":
        local = f"{first}{sep}{last[0]}{random.randint(1, 999)}"
    else:  # nickname
        local = f"{first}{random.randint(10, 9999)}"

    return f"{local}@{domain}"


def _random_ua() -> tuple[str, str]:
    """Return (user_agent_string, platform_os_segment) for a random browser."""
    chrome = random.choice(_CHROME_VERSIONS)
    os_seg = random.choice(
        _WIN_VERSIONS + _MAC_VERSIONS + _LINUX_VERSIONS
    )
    ua = (f"Mozilla/5.0 ({os_seg}) AppleWebKit/537.36 "
          f"(KHTML, like Gecko) Chrome/{chrome} Safari/537.36")
    return ua, os_seg


def fingerprint() -> dict:
    """Return a full fingerprint dict:
        ua, headers (dict ready for httpx/websockets), email
    Each call is a unique 'person'.
    """
    ua, os_seg = _random_ua()
    lang = random.choice(_LANGUAGES)
    email = _gen_realistic_email()

    # Determine sec-ch-ua-platform
    platform = '"Windows"'
    for key, val in _SEC_CH_PLATFORMS.items():
        if key in os_seg:
            platform = val
            break

    # Chrome major version for sec-ch-ua
    major = ua.split("Chrome/")[1].split(".")[0]

    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": lang,
        "Sec-Ch-Ua": f'"Chromium";v="{major}", "Google Chrome";v="{major}", "Not-A.Brand";v="99"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": platform,
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "Origin": "https://use.ai",
        "Referer": "https://use.ai/",
    }

    return {"ua": ua, "headers": headers, "email": email}
