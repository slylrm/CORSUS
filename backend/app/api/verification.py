"""
Domain Verification API Endpoints
Domain sahipliği doğrulama
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import secrets
import dns.resolver
from datetime import datetime, timedelta
import re
from urllib.parse import urlparse

from app.utils.logger import logger
from app.config import settings
from app.core.persistence import (
    get_latest_verification_status,
    get_verification_token,
    mark_verification_failure,
    mark_verification_success,
    save_verification_token,
)


router = APIRouter()

_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+(?::\d{1,5})?$", re.IGNORECASE)


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _normalize_domain(domain: str) -> str:
    if not domain or not isinstance(domain, str):
        raise HTTPException(status_code=400, detail="Domain is required")

    candidate = domain.strip().lower()
    if "://" in candidate:
        parsed = urlparse(candidate)
        if not parsed.hostname:
            raise HTTPException(status_code=400, detail="Invalid domain format")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise HTTPException(status_code=400, detail="Domain must not include paths or query parameters")
        candidate = parsed.hostname
        if parsed.port:
            candidate = f"{candidate}:{parsed.port}"

    if any(ch in candidate for ch in ("/", "@", " ")):
        raise HTTPException(status_code=400, detail="Domain must be a hostname only")

    if not _DOMAIN_RE.match(candidate):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    return candidate


class VerificationRequest(BaseModel):
    """Domain verification isteği"""
    domain: str


class VerificationResponse(BaseModel):
    """Verification token yanıtı"""
    domain: str
    verification_token: str
    verification_method: str
    instructions: str
    expires_at: datetime


class VerificationCheckRequest(BaseModel):
    """Verification kontrolü"""
    domain: str
    verification_token: str


class VerificationCheckResponse(BaseModel):
    """Verification sonucu"""
    domain: str
    verified: bool
    method_used: Optional[str] = None
    verified_at: Optional[datetime] = None
    error_message: Optional[str] = None


@router.post("/request", response_model=VerificationResponse)
async def request_verification(request: VerificationRequest):
    """
    Domain verification token oluştur
    
    Domain sahipliğini doğrulamak için:
    1. DNS TXT kaydı yöntemi (önerilen)
    2. HTML dosya yöntemi
    3. Meta tag yöntemi
    
    Args:
        domain: Doğrulanacak domain
        
    Returns:
        Verification token ve talimatlar
    """
    
    domain = _normalize_domain(request.domain)
    
    # Token oluştur
    verification_token = f"{settings.VERIFICATION_TOKEN_PREFIX}-{secrets.token_urlsafe(16)}"
    
    expires_at = datetime.now() + timedelta(hours=24)
    save_verification_token(domain=domain, token=verification_token, expires_at=expires_at)
    
    instructions = f"""
🔐 Domain Sahipliğini Doğrulama Talimatları

**Domain:** {domain}
**Token:** {verification_token}

Aşağıdaki yöntemlerden birini kullanarak domain sahipliğinizi doğrulayın:

---

**Yöntem 1: DNS TXT Kaydı (Önerilen)**

1. Domain DNS ayarlarınıza girin
2. Yeni bir TXT kaydı ekleyin:
   
   Kayıt Tipi: TXT
   Hostname: @ veya {domain}
   Değer: {verification_token}
   TTL: 3600 (veya default)

3. DNS değişikliğinin yayılmasını bekleyin (5-30 dakika)
4. "Doğrula" butonuna tıklayın

DNS propagation kontrolü:
```bash
nslookup -type=TXT {domain}
dig TXT {domain}
```

---

**Yöntem 2: HTML Dosyası**

1. Aşağıdaki içeriği içeren dosyayı oluşturun:
   
   Dosya adı: weppentest-verification.html
   İçerik: {verification_token}

2. Dosyayı sitenizin root dizinine yükleyin:
   https://{domain}/weppentest-verification.html

3. Dosyanın erişilebilir olduğundan emin olun
4. "Doğrula" butonuna tıklayın

---

**Yöntem 3: Meta Tag**

1. Sitenizin ana sayfasının <head> bölümüne ekleyin:
   
   <meta name="weppentest-verification" content="{verification_token}">

2. Değişikliği yayınlayın
3. "Doğrula" butonuna tıklayın

---

⏱️ Token süresi: {expires_at.strftime('%Y-%m-%d %H:%M:%S')}
📧 Sorun mu yaşıyorsunuz? support@weppentest.com
"""
    
    logger.info(f"Verification token created for domain: {domain}")
    
    return VerificationResponse(
        domain=domain,
        verification_token=verification_token,
        verification_method="dns_txt",
        instructions=instructions,
        expires_at=expires_at
    )


@router.post("/verify", response_model=VerificationCheckResponse)
async def verify_domain(request: VerificationCheckRequest):
    """
    Domain sahipliğini doğrula
    
    Verification methods:
    1. DNS TXT record check
    2. HTML file check
    3. Meta tag check
    
    Args:
        domain: Domain
        verification_token: Verification token
        
    Returns:
        Doğrulama sonucu
    """
    
    domain = _normalize_domain(request.domain)
    token = request.verification_token
    
    logger.info(f"Verifying domain: {domain}")

    token_record = get_verification_token(domain, token)
    if not token_record:
        raise HTTPException(status_code=404, detail="Verification token not found for this domain")

    expires_at = _parse_dt(token_record.get("expires_at"))
    now = datetime.now(expires_at.tzinfo) if expires_at and expires_at.tzinfo else datetime.now()

    if expires_at and now > expires_at:
        message = "Verification token expired. Please request a new token."
        mark_verification_failure(domain, token, message)
        return VerificationCheckResponse(
            domain=domain,
            verified=False,
            error_message=message,
        )

    if str(token_record.get("status", "")).lower() == "verified":
        return VerificationCheckResponse(
            domain=domain,
            verified=True,
            method_used=token_record.get("method_used"),
            verified_at=_parse_dt(token_record.get("verified_at")),
        )
    
    # Method 1: DNS TXT Record
    dns_verified, dns_error = await _check_dns_txt_record(domain, token)
    if dns_verified:
        logger.info(f"Domain verified via DNS: {domain}")
        mark_verification_success(domain, token, "dns_txt")
        return VerificationCheckResponse(
            domain=domain,
            verified=True,
            method_used="dns_txt",
            verified_at=datetime.now()
        )
    
    # Method 2: HTML File
    html_verified, html_error = await _check_html_file(domain, token)
    if html_verified:
        logger.info(f"Domain verified via HTML: {domain}")
        mark_verification_success(domain, token, "html_file")
        return VerificationCheckResponse(
            domain=domain,
            verified=True,
            method_used="html_file",
            verified_at=datetime.now()
        )
    
    # Method 3: Meta Tag
    meta_verified, meta_error = await _check_meta_tag(domain, token)
    if meta_verified:
        logger.info(f"Domain verified via Meta Tag: {domain}")
        mark_verification_success(domain, token, "meta_tag")
        return VerificationCheckResponse(
            domain=domain,
            verified=True,
            method_used="meta_tag",
            verified_at=datetime.now()
        )
    
    # Hiçbir yöntem başarılı olmadı
    error_messages = []
    if dns_error:
        error_messages.append(f"DNS: {dns_error}")
    if html_error:
        error_messages.append(f"HTML: {html_error}")
    if meta_error:
        error_messages.append(f"Meta: {meta_error}")

    error_text = " | ".join(error_messages)
    mark_verification_failure(domain, token, error_text)
    
    logger.warning(f"Domain verification failed: {domain}")
    
    return VerificationCheckResponse(
        domain=domain,
        verified=False,
        error_message=error_text
    )


async def _check_dns_txt_record(domain: str, token: str) -> tuple[bool, Optional[str]]:
    """DNS TXT kaydını kontrol et"""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        answers = resolver.resolve(domain, 'TXT')
        
        for rdata in answers:
            txt_value = rdata.to_text().strip('"')
            if token in txt_value:
                return True, None
        
        return False, "Token not found in DNS TXT records"
        
    except dns.resolver.NXDOMAIN:
        return False, "Domain does not exist"
    except dns.resolver.NoAnswer:
        return False, "No TXT records found"
    except dns.resolver.Timeout:
        return False, "DNS query timeout"
    except Exception as e:
        logger.error(f"DNS check error: {e}")
        return False, f"DNS error: {str(e)}"


async def _check_html_file(domain: str, token: str) -> tuple[bool, Optional[str]]:
    """HTML dosyasını kontrol et"""
    import httpx
    
    url = f"https://{domain}/weppentest-verification.html"
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(url, follow_redirects=True)
            
            if response.status_code == 200:
                if token in response.text:
                    return True, None
                else:
                    return False, "Token not found in file content"
            else:
                return False, f"File not accessible (HTTP {response.status_code})"
                
    except httpx.TimeoutException:
        return False, "HTTP request timeout"
    except Exception as e:
        logger.error(f"HTML check error: {e}")
        return False, f"HTTP error: {str(e)}"


async def _check_meta_tag(domain: str, token: str) -> tuple[bool, Optional[str]]:
    """Meta tag'i kontrol et"""
    import httpx
    from bs4 import BeautifulSoup
    
    url = f"https://{domain}"
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(url, follow_redirects=True)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                meta_tag = soup.find('meta', attrs={'name': 'weppentest-verification'})
                
                if meta_tag and meta_tag.get('content') == token:
                    return True, None
                else:
                    return False, "Meta tag not found or token mismatch"
            else:
                return False, f"Homepage not accessible (HTTP {response.status_code})"
                
    except Exception as e:
        logger.error(f"Meta tag check error: {e}")
        return False, f"Meta tag error: {str(e)}"


@router.get("/status/{domain}")
async def get_verification_status(domain: str):
    """
    Domain'in verification durumunu kontrol et
    
    Args:
        domain: Domain
        
    Returns:
        Verification durumu
    """
    
    domain = _normalize_domain(domain)
    latest = get_latest_verification_status(domain)

    if not latest:
        return {
            "domain": domain,
            "verified": False,
            "pending_token": None,
            "verified_at": None,
            "status": "not_requested",
        }

    status = str(latest.get("status") or "pending").lower()
    verified_at = _parse_dt(latest.get("verified_at"))
    expires_at = _parse_dt(latest.get("expires_at"))

    return {
        "domain": domain,
        "verified": status == "verified",
        "pending_token": latest.get("token") if status != "verified" else None,
        "verified_at": verified_at,
        "status": status,
        "method_used": latest.get("method_used"),
        "expires_at": expires_at,
        "last_error": latest.get("last_error"),
    }
