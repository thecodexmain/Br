"""
Braintree card-tokenizer API — Railway ready.
No API-key gate. Per-request proxy support (optional).

Proxy can be passed two ways:
  "proxy":   "host:port:user:pass"          (single)
  "proxies": ["host:port:user:pass", ...]   (list, rotates)

Fallback: env PROXY_URL / PROXY_LIST / PROXY_FILE, all optional.
"""

import os
import re
import json
import base64
import uuid
import threading
import logging
from typing import Optional, List, Union

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

# ---------------------------------------------------------------- config

SITE_BASE = os.environ.get("SITE_BASE", "https://www.kaffn8.com").rstrip("/")
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "30"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
DEBUG_ERRORS = os.environ.get("DEBUG_ERRORS", "").lower() in ("1", "true", "yes")

PROXY_URL = os.environ.get("PROXY_URL", "").strip()
PROXY_LIST_RAW = os.environ.get("PROXY_LIST", "")
PROXY_FILE = os.environ.get("PROXY_FILE", "").strip()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
)
log = logging.getLogger("cardtok")

app = FastAPI(title="Card Tokenizer API", version="2.1.0")


# ---------------------------------------------------------------- proxy helpers

def _parse_proxy_line(line: str) -> Optional[str]:
    """Accept host:port:user:pass OR full URL. Return requests-compatible URL."""
    if not line:
        return None
    line = str(line).strip()
    if not line or line.startswith("#"):
        return None
    if "://" in line:
        return line
    parts = line.split(":")
    if len(parts) == 4:
        host, port, user, pw = parts
        return f"http://{user}:{pw}@{host}:{port}"
    if len(parts) == 2:
        host, port = parts
        return f"http://{host}:{port}"
    return None


def _env_proxy_pool() -> List[str]:
    raw = []
    if PROXY_LIST_RAW:
        raw.extend(PROXY_LIST_RAW.splitlines())
    if PROXY_FILE and os.path.isfile(PROXY_FILE):
        try:
            with open(PROXY_FILE) as f:
                raw.extend(f.read().splitlines())
        except Exception as e:
            log.warning("could not read PROXY_FILE: %s", e)
    if PROXY_URL:
        raw.append(PROXY_URL)
    out = []
    for line in raw:
        p = _parse_proxy_line(line)
        if p and p not in out:
            out.append(p)
    return out


class ProxyRotator:
    """Per-request rotator. If given proxies, uses them. Otherwise env pool."""

    def __init__(self, proxies: Optional[List[str]] = None):
        if proxies is None:
            proxies = _env_proxy_pool()
        self._proxies = [p for p in (_parse_proxy_line(x) for x in proxies) if p]
        self._dead: set = set()
        self._idx = 0
        self._lock = threading.Lock()

    def _pick(self) -> Optional[dict]:
        with self._lock:
            if not self._proxies:
                return None
            for _ in range(len(self._proxies)):
                self._idx = (self._idx + 1) % len(self._proxies)
                p = self._proxies[self._idx]
                if p not in self._dead:
                    return {"http": p, "https": p}
            self._dead.clear()
            p = self._proxies[0]
            return {"http": p, "https": p}

    def mark_dead(self, proxies: Optional[dict]):
        if not proxies:
            return
        p = proxies.get("http")
        if p:
            with self._lock:
                self._dead.add(p)
            log.warning("proxy dead: %s", p.split("@")[-1] if "@" in p else p)

    def size(self) -> int:
        return len(self._proxies)

    def dead_count(self) -> int:
        return len(self._dead)


# ---------------------------------------------------------------- models

class CardIn(BaseModel):
    number: str = Field(..., min_length=12, max_length=19)
    expiration_month: str = Field(..., min_length=1, max_length=2)
    expiration_year: str = Field(..., min_length=2, max_length=4)
    cvv: str = Field(..., min_length=3, max_length=4)


class AccountIn(BaseModel):
    username: str
    password: str


class BillingIn(BaseModel):
    first_name: str = "Devesh"
    last_name: str = "K"
    address_1: str = "123 Main St"
    address_2: str = ""
    city: str = "New York"
    state: str = "NY"
    postcode: str = "10001"
    country: str = "US"
    phone: str = "5555550100"


ProxyField = Optional[Union[str, List[str]]]


class AddCardIn(BaseModel):
    account: AccountIn
    card: CardIn
    card_type: str = "visa"
    device_data_correlation_id: Optional[str] = None
    billing: BillingIn = BillingIn()
    proxy: ProxyField = None      # single: "host:port:user:pass" or full URL
    proxies: Optional[List[str]] = None  # list of the above


class AddCardOut(BaseModel):
    ok: bool
    token: Optional[str] = None
    woo_nonce: Optional[str] = None
    auth_fingerprint: Optional[str] = None
    raw_status_code: int
    message: str


class ListCardsIn(BaseModel):
    account: AccountIn
    proxy: ProxyField = None
    proxies: Optional[List[str]] = None


class SavedCard(BaseModel):
    last4: Optional[str] = None
    brand: Optional[str] = None
    expiry: Optional[str] = None
    raw_text: str


class ListCardsOut(BaseModel):
    ok: bool
    raw_status_code: int
    message: str
    cards: List[SavedCard] = []


class ProbeIn(BaseModel):
    proxy: ProxyField = None
    proxies: Optional[List[str]] = None


class ProbeOut(BaseModel):
    status_code: int
    server: Optional[str] = None
    content_type: Optional[str] = None
    title: Optional[str] = None
    has_login_form: bool
    body_snippet: str
    proxy_used: Optional[str] = None


# ---------------------------------------------------------------- helpers

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/154.0.0.0 Safari/537.36"
)
SEC_CH_UA = '"Chromium";v="154", "Brave";v="154", "Not A(Brand";v="99"'


def _base_headers() -> dict:
    return {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.5",
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-gpc": "1",
        "user-agent": UA,
    }


def _extract_woo_errors(body: str) -> List[str]:
    soup = BeautifulSoup(body, "html.parser")
    reasons: List[str] = []
    for sel in (
        "ul.woocommerce-error li",
        "ul.woocommerce-error",
        "ul.woocommerce-info li",
        "ul.woocommerce-info",
        "ul.woocommerce-message li",
        ".woocommerce-error",
        ".woocommerce-NoticeGroup-checkout",
    ):
        for el in soup.select(sel):
            t = el.get_text(" ", strip=True)
            if t and t not in reasons:
                reasons.append(t)
    if not reasons:
        for pat in (
            r"Status code \d+:\s*[^<\"]+",
            r"Reason:\s*[^<\"]+",
            r"Error:\s*[^<\"]+",
            r"declined[^<\".]*",
        ):
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                reasons.append(m.group(0).strip())
                break
    return reasons


def _make_rotator(proxy: ProxyField, proxies: Optional[List[str]]) -> ProxyRotator:
    """Build a rotator from whatever the caller supplied."""
    merged: List[str] = []
    if isinstance(proxy, str) and proxy.strip():
        merged.append(proxy.strip())
    elif isinstance(proxy, list):
        merged.extend([p for p in proxy if p])
    if proxies:
        merged.extend([p for p in proxies if p])
    if merged:
        return ProxyRotator(proxies=merged)
    return ProxyRotator(proxies=None)  # env fallback


def _new_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(_base_headers())
    return s


def _request(session: requests.Session, rotator: ProxyRotator, method: str, url: str, **kw) -> requests.Response:
    """Request through the rotator. On proxy failure, retry direct."""
    proxies = rotator._pick()
    kw.setdefault("timeout", REQUEST_TIMEOUT)
    try:
        return session.request(method, url, proxies=proxies, **kw)
    except (requests.exceptions.ProxyError,
            requests.exceptions.ConnectTimeout,
            requests.exceptions.ReadTimeout,
            requests.exceptions.ConnectionError) as e:
        if proxies:
            rotator.mark_dead(proxies)
            log.warning("proxy failed (%s), retrying direct", e.__class__.__name__)
        return session.request(method, url, proxies=None, **kw)


def _login(session: requests.Session, rotator: ProxyRotator, account: AccountIn) -> str:
    h1 = _base_headers()
    h1.update({
        "cache-control": "max-age=0",
        "priority": "u=0, i",
        "referer": f"{SITE_BASE}/my-account/",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
    })
    r1 = _request(session, rotator, "GET", f"{SITE_BASE}/my-account/", headers=h1)
    soup = BeautifulSoup(r1.text, "html.parser")
    login_nonce_el = soup.find("input", {"name": "woocommerce-login-nonce"})
    if not login_nonce_el:
        ct = r1.headers.get("content-type", "?")
        server = r1.headers.get("server", "?")
        title = soup.title.get_text(strip=True) if soup.title else "no-title"
        snippet = re.sub(r"\s+", " ", soup.get_text(" ", strip=True))[:600]
        raise HTTPException(
            status_code=502,
            detail=(
                f"login nonce not found | status={r1.status_code} "
                f"content-type={ct} server={server} title={title!r} "
                f"body_snippet={snippet!r}"
            ),
        )
    lnonce = login_nonce_el["value"]

    h2 = _base_headers()
    h2.update({
        "cache-control": "max-age=0",
        "content-type": "application/x-www-form-urlencoded",
        "origin": SITE_BASE,
        "priority": "u=0, i",
        "referer": f"{SITE_BASE}/my-account/",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
    })
    data_login = {
        "username": account.username,
        "password": account.password,
        "rememberme": "forever",
        "woocommerce-login-nonce": lnonce,
        "_wp_http_referer": "/my-account/",
        "login": "Log in",
    }
    r2 = _request(session, rotator, "POST", f"{SITE_BASE}/my-account/", headers=h2, data=data_login)
    if "woocommerce-error" in r2.text and "logout" not in r2.text.lower():
        errs = _extract_woo_errors(r2.text)
        raise HTTPException(status_code=401, detail=f"login failed: {' | '.join(errs) or 'unknown'}")
    return r2.text


# ---------------------------------------------------------------- core flows

def run_flow(account: AccountIn, card: CardIn, card_type: str,
             device_data_correlation_id: Optional[str],
             billing: BillingIn,
             rotator: ProxyRotator) -> AddCardOut:
    session = _new_session()
    _login(session, rotator, account)

    h3 = _base_headers()
    h3.update({
        "priority": "u=0, i",
        "referer": f"{SITE_BASE}/my-account/payment-methods/",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
    })
    r3 = _request(session, rotator, "GET", f"{SITE_BASE}/my-account/add-payment-method/", headers=h3)
    soup3 = BeautifulSoup(r3.text, "html.parser")

    woo_nonce_el = soup3.find("input", {"name": "woocommerce-add-payment-method-nonce"})
    if not woo_nonce_el:
        raise HTTPException(status_code=502, detail="woo add-payment-method nonce not found")
    woo_nonce = woo_nonce_el["value"]

    m = re.search(r'"client_token_nonce"\s*:\s*"([^"]+)"', r3.text)
    if not m:
        raise HTTPException(status_code=502, detail="client_token_nonce not found on page")
    client_token_nonce = m.group(1)

    h4 = _base_headers()
    h4.update({
        "accept": "*/*",
        "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        "origin": SITE_BASE,
        "priority": "u=1, i",
        "referer": f"{SITE_BASE}/my-account/add-payment-method/",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "x-requested-with": "XMLHttpRequest",
    })
    r4 = _request(
        session, rotator, "POST", f"{SITE_BASE}/wp-admin/admin-ajax.php",
        headers=h4,
        data={"action": "wc_braintree_credit_card_get_client_token", "nonce": client_token_nonce},
    )
    try:
        ajax_json = r4.json()
    except Exception:
        raise HTTPException(status_code=502, detail="admin-ajax returned non-json")

    data_field = ajax_json.get("data")
    if isinstance(data_field, str):
        client_token = data_field
    elif isinstance(data_field, dict):
        client_token = data_field.get("clientToken")
    else:
        client_token = None
    if not client_token:
        raise HTTPException(status_code=502, detail=f"clientToken missing in ajax response: {ajax_json}")

    token_data = json.loads(base64.b64decode(client_token))
    auth_fingerprint = token_data["authorizationFingerprint"]

    session_id = str(uuid.uuid4())
    correlation_id = device_data_correlation_id or session_id[:32]

    h5 = {
        "accept": "*/*",
        "accept-language": "en-US,en;q=0.5",
        "authorization": f"Bearer {auth_fingerprint}",
        "braintree-version": "2018-05-10",
        "content-type": "application/json",
        "origin": "https://assets.braintreegateway.com",
        "priority": "u=1, i",
        "referer": "https://assets.braintreegateway.com/",
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "cross-site",
        "sec-gpc": "1",
        "user-agent": UA,
    }

    year = card.expiration_year
    if len(year) == 2:
        year = "20" + year
    month = card.expiration_month.zfill(2)

    gql = {
        "clientSdkMetadata": {"source": "client", "integration": "custom", "sessionId": session_id},
        "query": (
            "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { "
            "  tokenizeCreditCard(input: $input) { token creditCard { bin brandCode last4 } } "
            "}"
        ),
        "variables": {
            "input": {
                "creditCard": {
                    "number": card.number,
                    "expirationMonth": month,
                    "expirationYear": year,
                    "cvv": card.cvv,
                    "billingAddress": {
                        "firstName": billing.first_name,
                        "lastName": billing.last_name,
                        "streetAddress": billing.address_1,
                        "extendedAddress": billing.address_2,
                        "locality": billing.city,
                        "region": billing.state,
                        "postalCode": billing.postcode,
                        "countryCodeAlpha2": billing.country,
                    },
                },
                "options": {"validate": False},
            }
        },
        "operationName": "TokenizeCreditCard",
    }

    r5 = _request(session, rotator, "POST",
                  "https://payments.braintree-api.com/graphql", headers=h5, json=gql)
    try:
        r5_json = r5.json()
    except Exception:
        raise HTTPException(status_code=502, detail=f"braintree non-json: {r5.text[:200]}")

    if "errors" in r5_json:
        return AddCardOut(
            ok=False, raw_status_code=r5.status_code,
            message=f"braintree graphql error: {r5_json['errors']}",
        )

    try:
        token = r5_json["data"]["tokenizeCreditCard"]["token"]
    except Exception:
        return AddCardOut(
            ok=False, raw_status_code=r5.status_code,
            message=f"token missing in braintree response: {str(r5_json)[:300]}",
        )

    h6 = _base_headers()
    h6.update({
        "cache-control": "max-age=0",
        "content-type": "application/x-www-form-urlencoded",
        "origin": SITE_BASE,
        "priority": "u=0, i",
        "referer": f"{SITE_BASE}/my-account/add-payment-method/",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
    })

    device_data = json.dumps({"correlation_id": correlation_id})

    data6 = [
        ("payment_method", "braintree_credit_card"),
        ("wc-braintree-credit-card-card-type", card_type),
        ("wc-braintree-credit-card-3d-secure-enabled", ""),
        ("wc-braintree-credit-card-3d-secure-verified", ""),
        ("wc-braintree-credit-card-3d-secure-order-total", "0.00"),
        ("wc_braintree_credit_card_payment_nonce", token),
        ("wc_braintree_device_data", device_data),
        ("wc-braintree-credit-card-tokenize-payment-method", "true"),
        ("wc-braintree-credit-card-billing-first-name", billing.first_name),
        ("wc-braintree-credit-card-billing-last-name", billing.last_name),
        ("wc-braintree-credit-card-billing-address-1", billing.address_1),
        ("wc-braintree-credit-card-billing-address-2", billing.address_2),
        ("wc-braintree-credit-card-billing-city", billing.city),
        ("wc-braintree-credit-card-billing-state", billing.state),
        ("wc-braintree-credit-card-billing-postcode", billing.postcode),
        ("wc-braintree-credit-card-billing-country", billing.country),
        ("wc-braintree-credit-card-billing-phone", billing.phone),
        ("wc_braintree_paypal_payment_nonce", ""),
        ("wc-braintree-paypal-context", "shortcode"),
        ("wc_braintree_paypal_amount", "0.00"),
        ("wc_braintree_paypal_currency", "USD"),
        ("wc-braintree-paypal-locale", "en_us"),
        ("wc-braintree-paypal-tokenize-payment-method", "true"),
        ("woocommerce-add-payment-method-nonce", woo_nonce),
        ("_wp_http_referer", "/my-account/add-payment-method/"),
        ("woocommerce_add_payment_method", "1"),
    ]

    r6 = _request(session, rotator, "POST",
                  f"{SITE_BASE}/my-account/add-payment-method/", headers=h6, data=data6)
    body = r6.text
    body_soup = BeautifulSoup(body, "html.parser")

    visible = body_soup.get_text(" ", strip=True).lower()
    success_markers = (
        "payment method added",
        "payment method successfully added",
        "payment method saved",
        "successfully added",
    )
    if any(mk in visible for mk in success_markers):
        return AddCardOut(
            ok=True, token=token, woo_nonce=woo_nonce,
            auth_fingerprint=auth_fingerprint,
            raw_status_code=r6.status_code,
            message="payment method added successfully",
        )

    reasons = _extract_woo_errors(body)
    reason = " | ".join(reasons) if reasons else "unknown decline"

    msg = f"DECLINED: {reason}"
    if DEBUG_ERRORS:
        msg += f" || DEBUG: {visible[:800]}"

    return AddCardOut(
        ok=False, token=token, woo_nonce=woo_nonce,
        auth_fingerprint=auth_fingerprint,
        raw_status_code=r6.status_code,
        message=msg,
    )


def run_list(account: AccountIn, rotator: ProxyRotator) -> ListCardsOut:
    session = _new_session()
    _login(session, rotator, account)

    h = _base_headers()
    h.update({
        "priority": "u=0, i",
        "referer": f"{SITE_BASE}/my-account/",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
    })
    r = _request(session, rotator, "GET", f"{SITE_BASE}/my-account/payment-methods/", headers=h)
    soup = BeautifulSoup(r.text, "html.parser")

    cards: List[SavedCard] = []
    for row in soup.select(".woocommerce-PaymentMethods .woocommerce-PaymentMethod, "
                          ".woocommerce-PaymentMethods tbody tr, "
                          ".woocommerce-PaymentMethod"):
        text = row.get_text(" ", strip=True)
        if not text:
            continue
        last4_m = re.search(r"(?:ending in|ending|••••|\*{4}|x{4})\s*(\d{4})", text, re.IGNORECASE)
        brand = None
        for b in ("visa", "mastercard", "amex", "american express", "discover", "jcb", "diners", "unionpay"):
            if b in text.lower():
                brand = b
                break
        exp_m = re.search(r"(\d{2})\s*/\s*(\d{2,4})", text)
        expiry = f"{exp_m.group(1)}/{exp_m.group(2)}" if exp_m else None
        cards.append(SavedCard(
            last4=last4_m.group(1) if last4_m else None,
            brand=brand,
            expiry=expiry,
            raw_text=text[:300],
        ))

    msg = "ok" if cards else "no saved methods found"
    return ListCardsOut(ok=True, raw_status_code=r.status_code, message=msg, cards=cards)


def run_probe(rotator: ProxyRotator) -> ProbeOut:
    session = _new_session()
    used = rotator._proxies[0] if rotator._proxies else None
    r = _request(session, rotator, "GET", f"{SITE_BASE}/my-account/")
    soup = BeautifulSoup(r.text, "html.parser")
    title = soup.title.get_text(strip=True) if soup.title else None
    has_form = bool(soup.find("input", {"name": "woocommerce-login-nonce"}))
    snippet = re.sub(r"\s+", " ", soup.get_text(" ", strip=True))[:800]
    return ProbeOut(
        status_code=r.status_code,
        server=r.headers.get("server"),
        content_type=r.headers.get("content-type"),
        title=title,
        has_login_form=has_form,
        body_snippet=snippet,
        proxy_used=(used.split("@")[-1] if used and "@" in used else used),
    )


def run_set_billing(account: AccountIn, billing: BillingIn, rotator: ProxyRotator) -> dict:
    session = _new_session()
    _login(session, rotator, account)

    h = _base_headers()
    h.update({
        "priority": "u=0, i",
        "referer": f"{SITE_BASE}/my-account/edit-address/",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
    })
    r = _request(session, rotator, "GET",
                 f"{SITE_BASE}/my-account/edit-address/billing/", headers=h)
    soup = BeautifulSoup(r.text, "html.parser")

    nonce_el = soup.find("input", {"name": "woocommerce-edit-address-nonce"})
    if not nonce_el:
        raise HTTPException(status_code=502, detail="edit-address nonce not found")
    nonce = nonce_el["value"]

    email = billing.first_name.lower() + "@example.com"
    email_el = soup.find("input", {"name": "billing_email"})
    if email_el and email_el.get("value"):
        email = email_el["value"]

    h2 = _base_headers()
    h2.update({
        "cache-control": "max-age=0",
        "content-type": "application/x-www-form-urlencoded",
        "origin": SITE_BASE,
        "priority": "u=0, i",
        "referer": f"{SITE_BASE}/my-account/edit-address/billing/",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
    })

    data = [
        ("billing_first_name", billing.first_name),
        ("billing_last_name", billing.last_name),
        ("billing_company", ""),
        ("billing_country", billing.country),
        ("billing_address_1", billing.address_1),
        ("billing_address_2", billing.address_2),
        ("billing_city", billing.city),
        ("billing_state", billing.state),
        ("billing_postcode", billing.postcode),
        ("billing_phone", billing.phone),
        ("billing_email", email),
        ("save_address", "Save address"),
        ("woocommerce-edit-address-nonce", nonce),
        ("_wp_http_referer", "/my-account/edit-address/billing/"),
        ("action", "edit_address"),
    ]

    r2 = _request(session, rotator, "POST",
                  f"{SITE_BASE}/my-account/edit-address/billing/",
                  headers=h2, data=data, allow_redirects=False)
    loc = r2.headers.get("location", "")
    if 300 <= r2.status_code < 400 and loc:
        follow = _request(session, rotator, "GET",
                          loc if loc.startswith("http") else SITE_BASE + loc)
        body = follow.text
    else:
        body = r2.text

    vis = BeautifulSoup(body, "html.parser").get_text(" ", strip=True)
    errs = _extract_woo_errors(body)
    ok = ("address changed successfully" in vis.lower()
          or any("successfully" in e.lower() or "saved" in e.lower() for e in errs))
    return {
        "ok": ok,
        "status": r2.status_code,
        "location": loc,
        "message": "billing address saved" if ok else (" | ".join(errs) or vis[:300]),
        "notices": errs,
    }


def run_get_billing(account: AccountIn, rotator: ProxyRotator) -> dict:
    session = _new_session()
    _login(session, rotator, account)

    h = _base_headers()
    h.update({
        "priority": "u=0, i",
        "referer": f"{SITE_BASE}/my-account/edit-address/",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
    })
    r = _request(session, rotator, "GET",
                 f"{SITE_BASE}/my-account/edit-address/billing/", headers=h)
    soup = BeautifulSoup(r.text, "html.parser")
    fields = {}
    for el in soup.find_all(["input", "select", "textarea"]):
        n = el.get("name")
        if not n or not n.startswith("billing_"):
            continue
        if el.name == "select":
            sel = el.find("option", selected=True)
            fields[n] = sel.get("value") if sel else el.get("value")
        else:
            fields[n] = el.get("value") or ""
    errs = _extract_woo_errors(r.text)
    return {"status": r.status_code, "fields": fields, "errors": errs}


# ---------------------------------------------------------------- routes

@app.get("/")
def root():
    return {"service": "card-tokenizer", "ok": True, "version": "2.1.0"}


@app.get("/health")
def health():
    env_pool = _env_proxy_pool()
    return {
        "ok": True,
        "version": "2.1.0",
        "debug_errors": DEBUG_ERRORS,
        "env_proxy_count": len(env_pool),
        "site_base": SITE_BASE,
    }


@app.post("/probe", response_model=ProbeOut)
def probe(payload: ProbeIn = ProbeIn()):
    try:
        rotator = _make_rotator(payload.proxy, payload.proxies)
        return run_probe(rotator)
    except HTTPException:
        raise
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"probe request failed: {e}")
    except Exception as e:
        log.exception("probe crashed")
        raise HTTPException(status_code=500, detail=f"internal error: {e}")


@app.post("/add-card", response_model=AddCardOut)
def add_card(payload: AddCardIn):
    rotator = _make_rotator(payload.proxy, payload.proxies)
    log.info("add-card user=%s card=****%s proxies=%d",
             payload.account.username, payload.card.number[-4:], rotator.size())
    try:
        result = run_flow(payload.account, payload.card,
                          payload.card_type, payload.device_data_correlation_id,
                          payload.billing, rotator)
    except HTTPException:
        raise
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"upstream request failed: {e}")
    except Exception as e:
        log.exception("flow crashed")
        raise HTTPException(status_code=500, detail=f"internal error: {e}")

    log.info("add-card result ok=%s msg=%s", result.ok, result.message)
    return result


@app.post("/list-cards", response_model=ListCardsOut)
def list_cards(payload: ListCardsIn):
    rotator = _make_rotator(payload.proxy, payload.proxies)
    log.info("list-cards user=%s proxies=%d", payload.account.username, rotator.size())
    try:
        return run_list(payload.account, rotator)
    except HTTPException:
        raise
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"upstream request failed: {e}")
    except Exception as e:
        log.exception("list crashed")
        raise HTTPException(status_code=500, detail=f"internal error: {e}")


@app.post("/set-billing")
def set_billing(payload: AddCardIn):
    rotator = _make_rotator(payload.proxy, payload.proxies)
    log.info("set-billing user=%s proxies=%d", payload.account.username, rotator.size())
    try:
        return run_set_billing(payload.account, payload.billing, rotator)
    except HTTPException:
        raise
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"upstream request failed: {e}")
    except Exception as e:
        log.exception("set-billing crashed")
        raise HTTPException(status_code=500, detail=f"internal error: {e}")


@app.post("/get-billing")
def get_billing(payload: ListCardsIn):
    rotator = _make_rotator(payload.proxy, payload.proxies)
    log.info("get-billing user=%s proxies=%d", payload.account.username, rotator.size())
    try:
        return run_get_billing(payload.account, rotator)
    except HTTPException:
        raise
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"upstream request failed: {e}")
    except Exception as e:
        log.exception("get-billing crashed")
        raise HTTPException(status_code=500, detail=f"internal error: {e}")
