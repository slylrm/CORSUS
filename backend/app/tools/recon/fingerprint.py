from __future__ import annotations

import asyncio
import re
from typing import Callable
from urllib.parse import urljoin

import aiohttp


ProgressCallback = Callable[[float, str], None]


class TechnologyFingerprinter:
    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    async def detect(
        self,
        target_url: str,
        session: aiohttp.ClientSession,
        progress_callback: ProgressCallback | None = None,
    ) -> dict:
        headers = {"User-Agent": "TaramaSecurityScanner/1.0"}
        try:
            async with session.get(
                target_url,
                headers=headers,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as response:
                body = await response.text(errors="ignore")
                findings = self._analyze(response.headers, body)

                active_probe_data = await self._active_probes(str(response.url), session, headers)
                for probe in active_probe_data:
                    for item in self._analyze(probe.get("headers", {}), probe.get("body", "")):
                        self._merge_technology(findings, item)
                    for item in self._analyze_probe_path(probe):
                        self._merge_technology(findings, item)

                if progress_callback:
                    progress_callback(1.0, "Teknoloji tespiti tamamlandi")
                return {
                    "url": str(response.url),
                    "status": response.status,
                    "technologies": findings,
                    "server_header": response.headers.get("Server"),
                    "headers": dict(response.headers),
                    "active_probe_count": len(active_probe_data),
                }
        except Exception as exc:
            if progress_callback:
                progress_callback(1.0, "Teknoloji tespiti basarisiz")
            return {
                "url": target_url,
                "status": None,
                "technologies": [],
                "server_header": None,
                "headers": {},
                "error": str(exc),
            }

    async def _active_probes(self, base_url: str, session: aiohttp.ClientSession, headers: dict) -> list[dict]:
        paths = [
            "/robots.txt",
            "/sitemap.xml",
            "/security.txt",
            "/.well-known/security.txt",
            "/wp-login.php",
            "/wp-admin/",
            "/administrator/",
            "/user/login",
            "/_next/static/",
            "/_nuxt/",
            "/assets/",
            "/api",
            "/api/v1/",
            "/graphql",
            "/swagger/index.html",
            "/openapi.json",
            "/actuator/health",
        ]
        results: list[dict] = []

        async def probe(path: str) -> None:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                async with session.get(
                    url,
                    headers=headers,
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=max(4.0, self.timeout * 0.7)),
                ) as response:
                    if response.status >= 500:
                        return
                    body = await response.text(errors="ignore")
                    results.append(
                        {
                            "path": path,
                            "url": str(response.url),
                            "status": response.status,
                            "headers": dict(response.headers),
                            "body": body[:3000],
                        }
                    )
            except Exception:
                return

        await asyncio.gather(*(probe(path) for path in paths), return_exceptions=True)
        return results

    def _analyze_probe_path(self, probe: dict) -> list[dict]:
        findings: list[dict] = []
        path = str(probe.get("path", "")).lower()
        status = probe.get("status")
        body = str(probe.get("body", "")).lower()
        headers = {str(k).lower(): str(v).lower() for k, v in (probe.get("headers") or {}).items()}
        location = headers.get("location", "")

        def add(name: str, category: str, evidence: str) -> None:
            findings.append({"name": name, "category": category, "evidence": evidence})

        if status in {200, 301, 302, 403}:
            if (
                "wordpress" in body
                or "wp-content" in body
                or "wp-login.php" in body
                or "wp-admin" in location
            ):
                add("WordPress", "cms", f"Active probe hit on {path}")
            if "joomla" in body or "com_content" in body or "/administrator/index.php" in location:
                add("Joomla", "cms", f"Active probe hit on {path}")
            if "drupal" in body or "x-drupal" in " ".join(f"{k}:{v}" for k, v in headers.items()):
                add("Drupal", "cms", f"Active probe hit on {path}")
            if "_next/static" in body or "__next" in body or headers.get("x-powered-by", "") == "next.js":
                add("Next.js", "frontend-framework", f"Active probe hit on {path}")
            if "_nuxt" in body or "__nuxt" in body:
                add("Nuxt.js", "frontend-framework", f"Active probe hit on {path}")
            if path == "/robots.txt" and "sitemap" in body:
                add("Robots/Sitemap", "metadata", "robots.txt content")
            if path in {"/swagger/index.html", "/openapi.json"}:
                add("OpenAPI/Swagger", "api-docs", f"Active probe hit on {path}")
            if path == "/graphql" and status in {200, 401, 403, 405}:
                add("GraphQL Endpoint", "api", f"GraphQL probe response on {path}")
            if path == "/actuator/health" and status in {200, 401, 403}:
                add("Spring Boot Actuator", "framework", f"Actuator probe response on {path}")

        if status in {403, 429}:
            if "cf-ray" in headers or "cloudflare" in headers.get("server", ""):
                add("Cloudflare WAF", "waf", f"{status} response with Cloudflare headers on {path}")
            if "x-sucuri-id" in headers:
                add("Sucuri WAF", "waf", f"{status} response with Sucuri headers on {path}")
            if "x-iinfo" in headers and "incap" in " ".join(f"{k}:{v}" for k, v in headers.items()):
                add("Imperva Incapsula", "waf", f"{status} response with Incapsula headers on {path}")
        return findings

    def _analyze(self, headers, body: str) -> list[dict]:
        technologies: list[dict] = []
        lower_body = body.lower()
        lower_headers = {key.lower(): value for key, value in headers.items()}
        merged_header_text = "\n".join(f"{k}: {v}" for k, v in lower_headers.items())

        def add(name: str, category: str, evidence: str) -> None:
            if not any(item["name"] == name for item in technologies):
                technologies.append(
                    {
                        "name": name,
                        "category": category,
                        "evidence": evidence,
                    }
                )

        server = headers.get("Server")
        if server:
            add(f"Server: {server}", "server", "Server header")

        # WAF/CDN/edge detection via known response headers and cookies.
        if "cf-ray" in lower_headers or "cf-cache-status" in lower_headers:
            add("Cloudflare", "cdn-waf", "CF-Ray/CF-Cache-Status header")
        if "cf-request-id" in lower_headers or "cloudflare" in lower_headers.get("server", ""):
            add("Cloudflare", "cdn-waf", "Cloudflare signature in headers")
        if "__cf_bm" in lower_headers.get("set-cookie", "") or "cf_clearance" in lower_headers.get("set-cookie", ""):
            add("Cloudflare Bot Management", "bot-protection", "Cloudflare bot cookie")

        if "x-sucuri-id" in lower_headers or "x-sucuri-cache" in lower_headers:
            add("Sucuri WAF", "waf", "Sucuri header")
        if "x-akamai" in merged_header_text or "akamai" in lower_headers.get("server", ""):
            add("Akamai", "cdn-waf", "Akamai header/server signature")
        if "x-iinfo" in lower_headers and "incap" in merged_header_text:
            add("Imperva Incapsula", "waf", "Incapsula header signature")
        if "x-cdn" in lower_headers and "imperva" in lower_headers.get("x-cdn", ""):
            add("Imperva", "waf", "X-CDN header indicates Imperva")
        if "x-firewall" in lower_headers:
            add("Firewall", "waf", "X-Firewall header")
        if "x-amzn-requestid" in lower_headers and "x-amz-cf-id" in lower_headers:
            add("AWS CloudFront", "cdn", "AWS edge headers")

        # CAPTCHA/challenge detection in HTML.
        if "www.google.com/recaptcha/" in lower_body or "www.gstatic.com/recaptcha/" in lower_body or "g-recaptcha" in lower_body:
            add("Google reCAPTCHA", "captcha", "reCAPTCHA marker in HTML")
        if "hcaptcha.com/1/api.js" in lower_body or "h-captcha" in lower_body:
            add("hCaptcha", "captcha", "hCaptcha marker in HTML")
        if "challenges.cloudflare.com/turnstile/" in lower_body or "cf-turnstile" in lower_body:
            add("Cloudflare Turnstile", "captcha", "Turnstile marker in HTML")
        if "cf-chl" in lower_body or "challenge-platform" in lower_body:
            add("Cloudflare Challenge", "bot-protection", "Cloudflare challenge marker in HTML")

        powered_by = headers.get("X-Powered-By") or headers.get("x-powered-by")
        if powered_by:
            add(f"X-Powered-By: {powered_by}", "framework", "X-Powered-By header")

        if "x-aspnet-version" in lower_headers or "x-aspnetmvc-version" in lower_headers:
            add("ASP.NET MVC", "framework", "ASP.NET version header")
        if "x-drupal-cache" in lower_headers or "x-drupal-dynamic-cache" in lower_headers:
            add("Drupal", "cms", "Drupal response header")
        if "x-shopify-stage" in lower_headers or "x-shopid" in lower_headers:
            add("Shopify", "cms", "Shopify response header")
        if "x-vercel-id" in lower_headers:
            add("Vercel", "hosting", "Vercel response header")
        if "x-served-by" in lower_headers and "fastly" in lower_headers.get("x-served-by", ""):
            add("Fastly", "cdn", "Fastly edge header")

        cookie_header = lower_headers.get("set-cookie", "")
        if "phpsessid" in cookie_header:
            add("PHP", "language", "PHP session cookie")
        if "asp.net_sessionid" in cookie_header:
            add("ASP.NET", "framework", "ASP.NET session cookie")
        if "jsessionid" in cookie_header:
            add("Java / J2EE", "framework", "JSESSIONID cookie")

        cms_patterns = [
            ("WordPress", "cms", ["wp-content", "wp-includes", "xmlrpc.php", 'name="generator" content="wordpress']),
            ("Joomla", "cms", ["content=\"joomla!", "/components/com_", "media/system/js"]),
            ("Drupal", "cms", ["drupal.settings", "sites/default/", 'content=\"drupal']),
            ("Magento", "cms", ["mage/cookies", 'content=\"magento', "/static/version"]),
            ("Shopify", "cms", ["cdn.shopify.com", "shopify.theme", 'content=\"shopify']),
        ]
        for name, category, needles in cms_patterns:
            if any(needle in lower_body for needle in needles):
                add(name, category, f"Matched body marker for {name}")

        framework_patterns = [
            ("React", "frontend-framework", ["data-reactroot", "reactdom", "__react_devtools_global_hook__"]),
            ("Angular", "frontend-framework", ["ng-version", "angular.js", "ng-app"]),
            ("Vue.js", "frontend-framework", ["__vue__", "vue.js", "data-v-"]),
            ("Next.js", "frontend-framework", ["__next_data__", "/_next/static/", "nextjs"]),
            ("Nuxt.js", "frontend-framework", ["__nuxt__", "/_nuxt/", "nuxt"]),
            ("Bootstrap", "frontend-framework", ["bootstrap.min.css", "bootstrap.bundle.min.js"]),
            ("Tailwind CSS", "frontend-framework", ["tailwindcss", "tailwind.min.css", "cdn.tailwindcss.com"]),
            ("jQuery", "frontend-framework", ["jquery.min.js", "code.jquery.com/jquery", "window.jquery"]),
        ]
        for name, category, needles in framework_patterns:
            if any(needle in lower_body for needle in needles):
                add(name, category, f"Matched body marker for {name}")

        if "server" in lower_headers:
            server_value = lower_headers["server"]
            if "nginx" in server_value:
                add("Nginx", "server", "Server header")
            elif "apache" in server_value:
                add("Apache", "server", "Server header")
            elif "iis" in server_value:
                add("IIS", "server", "Server header")
            elif "caddy" in server_value:
                add("Caddy", "server", "Server header")

        if "x-generator" in lower_headers:
            add(f"Generator: {lower_headers['x-generator']}", "metadata", "X-Generator header")

        for generator in re.findall(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", lower_body):
            add(f"Generator: {generator}", "metadata", "meta generator tag")

        for script_src in re.findall(r"<script[^>]+src=[\"']([^\"']+)", lower_body):
            src = script_src.lower()
            if "wp-includes" in src:
                add("WordPress", "cms", "Script source contains wp-includes")
            if "react" in src:
                add("React", "frontend-framework", "Script source contains react")
            if "angular" in src:
                add("Angular", "frontend-framework", "Script source contains angular")
            if "vue" in src:
                add("Vue.js", "frontend-framework", "Script source contains vue")

        return technologies

    @staticmethod
    def _merge_technology(target: list[dict], incoming: dict) -> None:
        for existing in target:
            if existing.get("name") == incoming.get("name"):
                return
        target.append(incoming)
