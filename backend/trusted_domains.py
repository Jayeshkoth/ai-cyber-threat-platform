from urllib.parse import urlparse


TRUSTED_DOMAINS = {
    "google.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "wikipedia.org",
    "youtube.com",
    "linkedin.com",
    "reddit.com",
    "stackoverflow.com",
}


def is_trusted_domain(url: str) -> bool:
    """
    Return True when the URL belongs to a known trusted domain.

    Examples:
        google.com -> True
        www.google.com -> True
        accounts.google.com -> True
        google.com.evil-site.com -> False
        evil-google.com -> False
    """

    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower().rstrip(".")

        for domain in TRUSTED_DOMAINS:
            if hostname == domain or hostname.endswith("." + domain):
                return True

        return False

    except Exception:
        return False