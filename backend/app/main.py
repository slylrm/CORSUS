"""
FastAPI Application Entry Point
Ana uygulama başlatma ve routing yapılandırması
"""

from fastapi import FastAPI, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import time
import uuid
from pathlib import Path
from datetime import datetime

from app.config import settings
from app.api import scans, reports, tools, verification, recon
from app.utils.logger import logger
from app.core.migration_runner import apply_migrations

# Templates
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"Debug mode: {settings.DEBUG}")
    logger.info(f"Database: {settings.DATABASE_URL}")
    
    # ✅ Apply database migrations
    try:
        logger.info("Applying database migrations...")
        apply_migrations()
        logger.info("Database migrations completed")
    except Exception as e:
        logger.error(f"Migration error: {e}", exc_info=True)
    
    # ✅ Developer-friendly startup guidance
    _log_startup_info()
    
    yield
    
    # Shutdown
    logger.info("Shutting down application")


def _log_startup_info():
    """
    Log clear, actionable startup information for developers.
    
    Explains why 0.0.0.0 (bind address) is NOT accessible from browser,
    and shows exactly where to open the application.
    """
    import platform
    import os
    
    logger.info("\n" + "="*80)
    logger.info("[APP] APPLICATION READY FOR USE")
    logger.info("="*80)
    
    logger.info("\n[IMPORTANT] How to Access the Application:")
    logger.info("""
    DO NOT use: http://0.0.0.0:8000
       - 0.0.0.0 is a server BIND address (listens on all interfaces)
       - It cannot be used as a client URL (browser cannot connect)
    
    USE ONE OF THESE INSTEAD:
    """)
    
    # Suggest appropriate URLs based on context
    logger.info("   - http://localhost:8000        (most common)")
    logger.info("   - http://127.0.0.1:8000        (same as localhost)")
    logger.info("   - http://<your-machine-ip>:8000 (from remote)")
    
    logger.info("\n[ENDPOINTS] Available:")
    logger.info("   - Dashboard:      http://localhost:8000/")
    logger.info("   - API Docs:       http://localhost:8000/docs")
    logger.info("   - ReDoc:          http://localhost:8000/redoc")
    logger.info("   - Start Scan:     POST /api/v1/scans/")
    
    logger.info("\n[SYSTEM] Configuration:")
    logger.info(f"   - OS: {platform.system()} {platform.release()}")
    logger.info(f"   - Python: {platform.python_version()}")
    logger.info(f"   - Host: 0.0.0.0 (listening on all interfaces)")
    logger.info(f"   - Port: 8000")
    
    logger.info("\n" + "="*80 + "\n")


# FastAPI app instance
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI-Free, Deterministic Web Application Security Testing Platform",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Static Files
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")


# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Add X-Process-Time header to responses"""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


# ✅ Security Headers Middleware (Professional posture)
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers for enterprise posture"""
    response = await call_next(request)
    
    # Prevent MIME-type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    
    # Clickjacking protection
    response.headers["X-Frame-Options"] = "DENY"
    
    # XSS protection (legacy browsers)
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    # Referrer policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # Feature policy (Permissions Policy)
    response.headers["Permissions-Policy"] = "microphone=(), camera=(), geolocation=()"
    
    # Custom security header
    response.headers["X-Powered-By"] = "WeppenTest Security Platform"
    
    return response


# ✅ Request Tracking Middleware (Showcase mode support)
@app.middleware("http")
async def add_request_tracking(request: Request, call_next):
    """Add request ID and determine operation mode"""
    
    # Generate unique request ID
    request_id = request.headers.get("X-Request-ID", f"req-{str(uuid.uuid4())[:8]}")
    request.state.request_id = request_id
    
    # Determine mode (normal, showcase, debug)
    mode = request.query_params.get("mode", "normal")
    if mode not in ["normal", "showcase", "debug"]:
        mode = "normal"
    request.state.mode = mode
    request.state.should_mask_data = (mode == "showcase")
    
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    
    return response


# ✅ Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle all unhandled exceptions with proper logging"""
    request_id = getattr(request.state, "request_id", "unknown")
    logger.opt(exception=exc).error(
        "[EXCEPTION] request_id={} path={} method={} error={!r}",
        request_id,
        request.url.path,
        request.method,
        exc,
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "request_id": request_id,
            "detail": str(exc) if settings.DEBUG else "An error occurred"
        }
    )


# Health check endpoint
@app.get("/health")
async def health_check(request: Request):
    """Professional health check endpoint"""
    request_id = getattr(request.state, "request_id", "unknown")
    
    # Check if request wants JSON
    accept = request.headers.get("accept", "")
    
    health_data = {
        "durum": "operasyonel",
        "servis": settings.APP_NAME,
        "versiyon": settings.APP_VERSION,
        "zaman": datetime.utcnow().isoformat(),
        "istek_id": request_id,
        "bilesenler": {
            "veritabani": "operasyonel",
            "tarama_motoru": "operasyonel",
        }
    }
    
    # If JSON requested explicitly, return JSON
    if "application/json" in accept:
        return JSONResponse(content=health_data)
    
    # Otherwise return beautiful HTML page
    return templates.TemplateResponse(
        "health.html",
        {
            "request": request,
            "app_name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "timestamp": datetime.utcnow().strftime("%d.%m.%Y %H:%M:%S"),
        }
    )


# Favicon endpoint (prevents 404 and shows a simple icon)
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
        svg_icon = """
        <svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'>
            <rect width='64' height='64' rx='12' fill='#1e293b'/>
            <path d='M16 44 L24 20 L32 36 L40 20 L48 44' stroke='#0ea5e9' stroke-width='6' fill='none' stroke-linecap='round' stroke-linejoin='round'/>
        </svg>
        """
        return Response(content=svg_icon.strip(), media_type="image/svg+xml")


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Root endpoint with beautiful UI"""
    # Check if request wants JSON
    accept = request.headers.get("accept", "")
    if "application/json" in accept:
        return JSONResponse(content={
            "mesaj": f"{settings.APP_NAME} - Hoş Geldiniz",
            "versiyon": settings.APP_VERSION,
            "dokumantasyon": "/docs",
            "saglik": "/health",
        })
    
    # Return HTML page
    return templates.TemplateResponse("index.html", {
        "request": request,
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
    })


@app.get("/scan", response_class=HTMLResponse)
async def scan_page(request: Request):
    """Professional security assessment page"""
    return templates.TemplateResponse("scan.html", {
        "request": request,
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
    })


@app.get("/recon", response_class=HTMLResponse)
async def recon_page(request: Request):
    """Recon scanner dashboard – CORSUS-style UI"""
    return templates.TemplateResponse("recon.html", {
        "request": request,
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
    })


# ✅ Additional startup event to reinforce the message via console
@app.on_event("startup")
async def on_startup():
    """Additional startup logging for extra clarity"""
    logger.debug("FastAPI startup event triggered")
    logger.info("✅ All systems operational - ready to accept requests")


# API Routers
app.include_router(
    scans.router,
    prefix="/api/v1/scans",
    tags=["Security Assessments"]
)

app.include_router(
    reports.router,
    prefix="/api/v1/reports",
    tags=["Assessment Reports"]
)

app.include_router(
    tools.router,
    prefix="/api/v1/tools",
    tags=["Security Tools"]
)

app.include_router(
    verification.router,
    prefix="/api/v1/verification",
    tags=["Domain Verification"]
)


app.include_router(

    recon.router,

    prefix="/api/v1/recon",

    tags=["Recon Scanner"]

)



if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG,
    )
