import argparse
import os
import secrets
import time
import webbrowser
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qs, unquote

import requests
from dotenv import load_dotenv


load_dotenv(override=True)


# -----------------------------------------------------------------------------
# Environment
# -----------------------------------------------------------------------------

TIKTOK_CLIENT_KEY = os.getenv("TIKTOK_CLIENT_KEY", "").strip()
TIKTOK_CLIENT_SECRET = os.getenv("TIKTOK_CLIENT_SECRET", "").strip()

TIKTOK_REDIRECT_URI = os.getenv(
    "TIKTOK_REDIRECT_URI",
    "https://karabuluti.github.io/darktruths-site/tiktok-callback.html",
).strip()

TIKTOK_SCOPES = os.getenv(
    "TIKTOK_SCOPES",
    "user.info.basic,video.upload",
).strip()

TIKTOK_API_BASE = os.getenv(
    "TIKTOK_API_BASE",
    "https://open.tiktokapis.com",
).strip().rstrip("/")

TIKTOK_AUTHORIZE_URL = "https://www.tiktok.com/v2/auth/authorize/"
TIKTOK_TOKEN_URL = f"{TIKTOK_API_BASE}/v2/oauth/token/"

DOTENV_PATH = Path(".env")


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def require_env():
    missing = []

    if not TIKTOK_CLIENT_KEY:
        missing.append("TIKTOK_CLIENT_KEY")

    if not TIKTOK_CLIENT_SECRET:
        missing.append("TIKTOK_CLIENT_SECRET")

    if not TIKTOK_REDIRECT_URI:
        missing.append("TIKTOK_REDIRECT_URI")

    if not TIKTOK_SCOPES:
        missing.append("TIKTOK_SCOPES")

    if missing:
        raise RuntimeError(
            ".env içinde eksik TikTok ayarı var: "
            + ", ".join(missing)
        )


def mask_secret(value: str, keep_start: int = 6, keep_end: int = 4) -> str:
    value = str(value or "")

    if len(value) <= keep_start + keep_end:
        return "*" * len(value)

    return f"{value[:keep_start]}...{value[-keep_end:]}"


def build_authorize_url(state: str) -> str:
    params = {
        "client_key": TIKTOK_CLIENT_KEY,
        "response_type": "code",
        "scope": TIKTOK_SCOPES,
        "redirect_uri": TIKTOK_REDIRECT_URI,
        "state": state,
        "disable_auto_auth": "1",
    }

    return f"{TIKTOK_AUTHORIZE_URL}?{urlencode(params)}"


def extract_code_and_state(raw_input_value: str) -> tuple[str, str]:
    text = (raw_input_value or "").strip()

    if not text:
        raise RuntimeError("Authorization code boş.")

    # Kullanıcı direkt code yapıştırdıysa.
    if "://" not in text and "code=" not in text:
        return unquote(text), ""

    parsed = urlparse(text)
    query = parse_qs(parsed.query)

    code_values = query.get("code") or []
    state_values = query.get("state") or []
    error_values = query.get("error") or []
    error_desc_values = query.get("error_description") or []

    if error_values:
        error = error_values[0]
        error_description = error_desc_values[0] if error_desc_values else ""
        raise RuntimeError(f"TikTok OAuth error: {error} {error_description}")

    if not code_values:
        raise RuntimeError(
            "Callback URL içinde code bulunamadı. "
            "tiktok-callback.html sayfasındaki Authorization code alanını kopyala."
        )

    code = unquote(code_values[0])
    state = state_values[0] if state_values else ""

    return code, state


def post_form(url: str, data: dict) -> dict:
    response = requests.post(
        url,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Cache-Control": "no-cache",
        },
        data=data,
        timeout=60,
    )

    try:
        payload = response.json()
    except Exception:
        payload = {
            "raw_text": response.text,
        }

    if not response.ok:
        raise RuntimeError(
            f"TikTok API error HTTP {response.status_code}\n"
            f"URL: {url}\n"
            f"Response: {payload}"
        )

    if isinstance(payload, dict) and payload.get("error"):
        raise RuntimeError(
            "TikTok API error\n"
            f"error: {payload.get('error')}\n"
            f"error_description: {payload.get('error_description')}\n"
            f"log_id: {payload.get('log_id')}"
        )

    return payload


def exchange_code_for_token(code: str) -> dict:
    data = {
        "client_key": TIKTOK_CLIENT_KEY,
        "client_secret": TIKTOK_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": TIKTOK_REDIRECT_URI,
    }

    return post_form(TIKTOK_TOKEN_URL, data=data)


def refresh_access_token(refresh_token: str) -> dict:
    if not refresh_token:
        raise RuntimeError("TIKTOK_REFRESH_TOKEN boş. Önce authorization_code flow çalıştır.")

    data = {
        "client_key": TIKTOK_CLIENT_KEY,
        "client_secret": TIKTOK_CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }

    return post_form(TIKTOK_TOKEN_URL, data=data)


def read_env_lines(path: Path) -> list[str]:
    if not path.exists():
        return []

    return path.read_text(encoding="utf-8").splitlines()


def update_env_file(path: Path, updates: dict[str, str]) -> None:
    timestamp = time.strftime("%Y%m%d-%H%M%S")

    if path.exists():
        backup_path = path.with_name(f"{path.name}.bak-tiktok-oauth-{timestamp}")
        backup_path.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        print(f".env backup oluşturuldu: {backup_path}")

    lines = read_env_lines(path)
    output_lines = []
    seen_keys = set()

    for line in lines:
        stripped = line.strip()

        if not stripped or stripped.startswith("#") or "=" not in line:
            output_lines.append(line)
            continue

        key = line.split("=", 1)[0].strip()

        if key in updates:
            output_lines.append(f"{key}={updates[key]}")
            seen_keys.add(key)
        else:
            output_lines.append(line)

    if output_lines and output_lines[-1].strip():
        output_lines.append("")

    output_lines.append("# TikTok OAuth tokens")
    for key, value in updates.items():
        if key not in seen_keys:
            output_lines.append(f"{key}={value}")

    path.write_text("\n".join(output_lines) + "\n", encoding="utf-8")


def build_env_updates(token_payload: dict) -> dict[str, str]:
    access_token = token_payload.get("access_token", "")
    refresh_token = token_payload.get("refresh_token", "")
    open_id = token_payload.get("open_id", "")
    scope = token_payload.get("scope", "")
    token_type = token_payload.get("token_type", "")
    expires_in = str(token_payload.get("expires_in", ""))
    refresh_expires_in = str(token_payload.get("refresh_expires_in", ""))

    if not access_token:
        raise RuntimeError(f"TikTok token response içinde access_token yok: {token_payload}")

    updates = {
        "TIKTOK_ACCESS_TOKEN": access_token,
        "TIKTOK_REFRESH_TOKEN": refresh_token,
        "TIKTOK_OPEN_ID": open_id,
        "TIKTOK_GRANTED_SCOPES": scope,
        "TIKTOK_TOKEN_TYPE": token_type,
        "TIKTOK_EXPIRES_IN": expires_in,
        "TIKTOK_REFRESH_EXPIRES_IN": refresh_expires_in,
        "TIKTOK_TOKEN_UPDATED_AT": str(int(time.time())),
    }

    return updates


def print_token_summary(token_payload: dict):
    print()
    print("=" * 90)
    print("TikTok OAuth token alındı")
    print("=" * 90)
    print("open_id:", token_payload.get("open_id", ""))
    print("scope:", token_payload.get("scope", ""))
    print("token_type:", token_payload.get("token_type", ""))
    print("expires_in:", token_payload.get("expires_in", ""))
    print("refresh_expires_in:", token_payload.get("refresh_expires_in", ""))
    print("access_token:", mask_secret(token_payload.get("access_token", "")))
    print("refresh_token:", mask_secret(token_payload.get("refresh_token", "")))
    print("=" * 90)
    print()


# -----------------------------------------------------------------------------
# Main flows
# -----------------------------------------------------------------------------

def run_authorization_flow(args):
    state = secrets.token_urlsafe(24)
    auth_url = build_authorize_url(state)

    print("=" * 90)
    print("TikTok OAuth setup")
    print("=" * 90)
    print("Client key:", mask_secret(TIKTOK_CLIENT_KEY))
    print("Redirect URI:", TIKTOK_REDIRECT_URI)
    print("Scopes:", TIKTOK_SCOPES)
    print("Expected state:", state)
    print()
    print("Auth URL:")
    print(auth_url)
    print()

    if not args.no_open:
        print("Tarayıcı açılıyor...")
        webbrowser.open(auth_url)

    print()
    print("TikTok login/authorize sonrası callback sayfası açılacak:")
    print(TIKTOK_REDIRECT_URI)
    print()
    print("Callback sayfasındaki Authorization code alanını veya full callback URL'yi buraya yapıştır.")
    raw_code = input("Code veya callback URL: ").strip()

    code, returned_state = extract_code_and_state(raw_code)

    if returned_state:
        print("Returned state:", returned_state)

        if returned_state != state:
            raise RuntimeError(
                "State mismatch. Güvenlik için token alınmadı. "
                "Auth URL'yi bu scriptin ürettiği URL'den tekrar aç."
            )
    else:
        print("State callback içinde yok veya direkt code yapıştırıldı; devam ediliyor.")

    print("Authorization code alındı. Token exchange yapılıyor...")

    token_payload = exchange_code_for_token(code)

    print_token_summary(token_payload)

    updates = build_env_updates(token_payload)

    if args.no_dotenv:
        print(".env yazılmadı. Aşağıdaki değerleri manuel ekle:")
        for key, value in updates.items():
            print(f"{key}={value}")
    else:
        update_env_file(DOTENV_PATH, updates)
        print(".env TikTok token değerleriyle güncellendi.")


def run_refresh_flow(args):
    refresh_token = os.getenv("TIKTOK_REFRESH_TOKEN", "").strip()

    print("=" * 90)
    print("TikTok OAuth refresh")
    print("=" * 90)
    print("Client key:", mask_secret(TIKTOK_CLIENT_KEY))
    print("Refresh token:", mask_secret(refresh_token))
    print()

    token_payload = refresh_access_token(refresh_token)

    print_token_summary(token_payload)

    updates = build_env_updates(token_payload)

    if args.no_dotenv:
        print(".env yazılmadı. Aşağıdaki değerleri manuel ekle:")
        for key, value in updates.items():
            print(f"{key}={value}")
    else:
        update_env_file(DOTENV_PATH, updates)
        print(".env refresh edilmiş TikTok token değerleriyle güncellendi.")


def main():
    parser = argparse.ArgumentParser(
        description="TikTok OAuth setup for DarkTruths Automation."
    )

    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Mevcut TIKTOK_REFRESH_TOKEN ile access_token yenile.",
    )

    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Tarayıcıyı otomatik açma; auth URL'yi sadece yazdır.",
    )

    parser.add_argument(
        "--no-dotenv",
        action="store_true",
        help=".env dosyasını güncelleme; tokenları sadece terminale yaz.",
    )

    args = parser.parse_args()

    require_env()

    if args.refresh:
        run_refresh_flow(args)
    else:
        run_authorization_flow(args)


if __name__ == "__main__":
    main()