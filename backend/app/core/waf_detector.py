"""
WAF Detection Service
Web Application Firewall ve Protection Layers Tespit Eder
"""

from typing import Optional, Dict, Any, List
from dataclasses import dataclass
import re
import requests
from app.utils.logger import logger
import time


@dataclass
class WAFDetection:
    """WAF Tespit Sonucu"""
    detected: bool
    vendor: Optional[str] = None
    confidence_score: float = 0.0
    detection_method: str = ""
    details: Dict[str, Any] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected": self.detected,
            "vendor": self.vendor,
            "confidence_score": self.confidence_score,
            "detection_method": self.detection_method,
            "details": self.details or {},
        }


@dataclass
class RateLimitDetection:
    """Rate Limit Tespit Sonucu"""
    detected: bool
    threshold: Optional[int] = None  # requests per minute
    status_code: int = 429
    confidence_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected": self.detected,
            "threshold": self.threshold,
            "status_code": self.status_code,
            "confidence_score": self.confidence_score,
        }


@dataclass
class BotProtectionDetection:
    """Bot Protection Tespit Sonucu"""
    detected: bool
    captcha_detected: bool = False
    javascript_check: bool = False
    user_agent_check: bool = False
    confidence_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected": self.detected,
            "captcha_detected": self.captcha_detected,
            "javascript_check": self.javascript_check,
            "user_agent_check": self.user_agent_check,
            "confidence_score": self.confidence_score,
        }


class WAFDetector:
    """Web Application Firewall tespit eder (Passive + Active)"""
    
    # WAF fingerprints database
    WAF_SIGNATURES = {
        "cloudflare": {
            "headers": ["CF-RAY", "CF-CACHE-STATUS", "CF-REQUEST-ID"],
            "cookies": ["__cfduid", "cf_clearance"],
            "patterns": [r"Cloudflare", r"cf-mitigated"],
            "error_pages": [r"Sorry.*reviewing your browser", r"Enable JavaScript"],
        },
        "akamai": {
            "headers": ["X-Akamai-Transformed", "X-Akamai-Staging"],
            "patterns": [r"AkamaiGHost"],
        },
        "aws_waf": {
            "headers": ["X-Amzn-ErrorType", "X-Amzn-RequestId"],
            "patterns": [r"AWS WAF", r"WAFAuthToken"],
        },
        "imperva": {
            "headers": ["X-Imperva-Incident-ID", "X-Imperva-RateLimit-Remaining"],
            "patterns": [r"Imperva", r"Incapsula"],
        },
        "mod_security": {
            "patterns": [r"mod_security", r"ModSecurity"],
            "error_patterns": [r"403 Forbidden.*ModSecurity"],
        },
    }
    
    def __init__(self):
        self.logger = logger.bind(component="WAFDetector")
        self.session = requests.Session()
        self.session.verify = False
    
    def detect_all_protections(self, target_url: str) -> Dict[str, Any]:
        """Tüm koruma katmanlarını tespit et"""
        
        result = {
            "waf": self.detect_waf(target_url).to_dict(),
            "rate_limiting": self.detect_rate_limiting(target_url).to_dict(),
            "bot_protection": self.detect_bot_protection(target_url).to_dict(),
        }
        
        self.logger.info(f"Protection detection complete for {target_url}")
        
        return result
    
    def detect_waf(self, target_url: str) -> WAFDetection:
        """WAF'ı passive + aktif olarak tespit et"""
        
        try:
            # 1. Passive detection - Response headers
            response = self._safe_request(target_url)
            if response:
                vendor = self._check_headers_passive(response.headers)
                if vendor:
                    return WAFDetection(
                        detected=True,
                        vendor=vendor,
                        confidence_score=0.90,
                        detection_method="header_fingerprinting",
                        details={"detected_headers": dict(response.headers)}
                    )
                
                # 2. Passive detection - Cookies
                vendor = self._check_cookies_passive(response.cookies)
                if vendor:
                    return WAFDetection(
                        detected=True,
                        vendor=vendor,
                        confidence_score=0.85,
                        detection_method="cookie_analysis",
                        details={"cookies": list(response.cookies.keys())}
                    )
                
                # 3. Passive detection - Error page patterns
                vendor = self._check_error_page_passive(response.text)
                if vendor:
                    return WAFDetection(
                        detected=True,
                        vendor=vendor,
                        confidence_score=0.75,
                        detection_method="error_page_analysis"
                    )
            
            # 4. Active detection - Payload testing
            return self._active_waf_detection(target_url)
        
        except Exception as e:
            self.logger.error(f"WAF detection error: {e}")
            return WAFDetection(detected=False)
    
    def _check_headers_passive(self, headers: Dict) -> Optional[str]:
        """Response header'larını kontrol et"""
        
        for vendor, sig in self.WAF_SIGNATURES.items():
            for header in sig.get("headers", []):
                if header in headers:
                    self.logger.info(f"WAF detected via header: {vendor} ({header})")
                    return vendor
        
        return None
    
    def _check_cookies_passive(self, cookies) -> Optional[str]:
        """Cookie'leri kontrol et"""
        
        cookie_names = [c.name if hasattr(c, 'name') else c for c in cookies]
        
        for vendor, sig in self.WAF_SIGNATURES.items():
            for cookie in sig.get("cookies", []):
                if cookie in cookie_names:
                    self.logger.info(f"WAF detected via cookie: {vendor} ({cookie})")
                    return vendor
        
        return None
    
    def _check_error_page_passive(self, html: str) -> Optional[str]:
        """Error page pattern'lerini kontrol et"""
        
        for vendor, sig in self.WAF_SIGNATURES.items():
            for pattern in sig.get("error_pages", []):
                if re.search(pattern, html, re.IGNORECASE):
                    self.logger.info(f"WAF detected via error page: {vendor}")
                    return vendor
        
        return None
    
    def _active_waf_detection(self, target_url: str) -> WAFDetection:
        """Aktif WAF davranış testi - Payload'ları test et"""
        
        # SQL Injection payloads (various encodings)
        payloads = [
            ("' OR '1'='1", "basic_sql_injection"),
            ("%27%20OR%20%271%27%3D%271", "url_encoded_sql"),
            ("' OR \"1\"=\"1", "double_quote_sql"),
            ("<script>alert('xss')</script>", "basic_xss"),
            ("%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E", "encoded_xss"),
            ("../../../etc/passwd", "path_traversal"),
            ("union select null--", "union_based_sql"),
        ]
        
        blocked_count = 0
        blocked_payloads = []
        
        for payload, description in payloads:
            try:
                response = self._safe_request(f"{target_url}?test={payload}", timeout=3)
                
                if response and response.status_code in [403, 405, 406, 429]:
                    blocked_count += 1
                    blocked_payloads.append((description, response.status_code))
                    self.logger.debug(f"Payload blocked: {description} ({response.status_code})")
            except Exception as e:
                blocked_count += 1
                blocked_payloads.append((description, "timeout/error"))
        
        # Değerlendirme
        block_ratio = blocked_count / len(payloads) if payloads else 0
        
        if block_ratio >= 0.5:
            confidence = min(0.5 + block_ratio * 0.3, 0.85)
            return WAFDetection(
                detected=True,
                vendor="Unknown WAF (Active Behavior)",
                confidence_score=confidence,
                detection_method="active_payload_testing",
                details={
                    "payloads_blocked": blocked_count,
                    "total_payloads": len(payloads),
                    "block_ratio": block_ratio,
                    "blocked_payloads": blocked_payloads,
                }
            )
        
        return WAFDetection(detected=False)
    
    def detect_rate_limiting(self, target_url: str) -> RateLimitDetection:
        """Rate limit tespit et"""
        
        try:
            threshold = 60  # Default threshold
            request_count = 0
            blocked_responses = 0
            
            # Hızlı bir şekilde multiple request gönder
            start_time = time.time()
            
            for i in range(20):  # 20 request
                try:
                    response = self._safe_request(f"{target_url}?seq={i}", timeout=2)
                    
                    if response:
                        request_count += 1
                        
                        if response.status_code == 429:
                            blocked_responses += 1
                            
                            # Rate-Limit header'ından threshold oku
                            if "X-RateLimit-Limit" in response.headers:
                                try:
                                    threshold = int(response.headers["X-RateLimit-Limit"])
                                except:
                                    pass
                
                except:
                    pass
                
                time.sleep(0.1)  # 100ms delay
            
            elapsed = time.time() - start_time
            
            if blocked_responses > 0:
                confidence = min(0.5 + (blocked_responses / 20) * 0.4, 0.9)
                self.logger.info(f"Rate limiting detected: {blocked_responses}/{request_count} blocked")
                
                return RateLimitDetection(
                    detected=True,
                    threshold=threshold,
                    status_code=429,
                    confidence_score=confidence,
                )
            
            return RateLimitDetection(detected=False)
        
        except Exception as e:
            self.logger.warning(f"Rate limit detection error: {e}")
            return RateLimitDetection(detected=False)
    
    def detect_bot_protection(self, target_url: str) -> BotProtectionDetection:
        """Bot protection (CAPTCHA, JS checks) tespit et"""
        
        try:
            response = self._safe_request(target_url)
            
            if not response:
                return BotProtectionDetection(detected=False)
            
            html = response.text.lower()
            
            # CAPTCHA detection
            captcha_detected = any([
                "hcaptcha" in html,
                "recaptcha" in html,
                "captcha" in html,
                "g_recaptchatoken" in html,
            ])
            
            # JavaScript check detection
            js_check = any([
                "document.location" in html,
                "__RequestVerificationToken" in html,
                "var _cf_challenge" in html,
            ])
            
            # User-Agent check (403 with unusual UA)
            ua_check = False
            unusual_ua_response = self._safe_request(
                target_url,
                headers={"User-Agent": "WeppenTest/1.0 Security Scanner"}
            )
            if unusual_ua_response and unusual_ua_response.status_code in [403, 405]:
                ua_check = True
            
            detected = captcha_detected or js_check or ua_check
            confidence = sum([captcha_detected * 0.35, js_check * 0.35, ua_check * 0.3])
            
            if detected:
                self.logger.info(f"Bot protection detected: CAPTCHA={captcha_detected}, JS={js_check}, UA={ua_check}")
            
            return BotProtectionDetection(
                detected=detected,
                captcha_detected=captcha_detected,
                javascript_check=js_check,
                user_agent_check=ua_check,
                confidence_score=confidence,
            )
        
        except Exception as e:
            self.logger.warning(f"Bot protection detection error: {e}")
            return BotProtectionDetection(detected=False)
    
    def _safe_request(self, url: str, timeout: int = 5, headers: Dict = None) -> Optional[requests.Response]:
        """Güvenli HTTP request yap"""
        
        try:
            req_headers = headers or {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            
            response = self.session.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers=req_headers,
            )
            
            return response
        
        except Exception as e:
            self.logger.debug(f"Safe request failed: {e}")
            return None
