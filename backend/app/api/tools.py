"""
Tools API Endpoints
Mevcut araçları listele ve bilgi sağla
"""

from fastapi import APIRouter
from typing import List, Dict, Any
from pydantic import BaseModel

from app.utils.logger import logger


router = APIRouter()


class ToolInfo(BaseModel):
    """Tool bilgisi"""
    name: str
    category: str
    description: str
    version: str
    installed: bool
    requires_sudo: bool


@router.get("/", response_model=List[ToolInfo])
async def list_tools():
    """
    Mevcut tüm pentest araçlarını listele
    
    Returns:
        Tool listesi
    """
    
    # TODO: Dinamik olarak tools/ klasöründen detect et
    
    tools = [
        ToolInfo(
            name="sqlmap",
            category="injection",
            description="Automatic SQL injection and database takeover tool",
            version="1.8",
            installed=True,
            requires_sudo=False
        ),
        ToolInfo(
            name="nmap",
            category="discovery",
            description="Network mapper and port scanner",
            version="7.94",
            installed=True,
            requires_sudo=False
        ),
        ToolInfo(
            name="nikto",
            category="misconfiguration",
            description="Web server scanner",
            version="2.5.0",
            installed=False,
            requires_sudo=False
        ),
        ToolInfo(
            name="xsstrike",
            category="injection",
            description="XSS detection and exploitation tool",
            version="3.1.5",
            installed=False,
            requires_sudo=False
        ),
    ]
    
    return tools


@router.get("/{tool_name}")
async def get_tool_info(tool_name: str) -> Dict[str, Any]:
    """
    Belirli bir aracın detaylı bilgisini getir
    
    Args:
        tool_name: Tool adı
        
    Returns:
        Tool detayları
    """
    
    # TODO: Dinamik olarak tool wrapper'dan bilgi al
    
    return {
        "name": tool_name,
        "category": "injection",
        "description": "Tool description",
        "version": "1.0",
        "installed": True,
        "capabilities": [
            "SQL injection detection",
            "Database fingerprinting",
        ],
        "options": {
            "level": {
                "type": "int",
                "range": [1, 5],
                "default": 1,
                "description": "Test derinliği"
            },
            "risk": {
                "type": "int",
                "range": [1, 3],
                "default": 1,
                "description": "Risk seviyesi"
            }
        }
    }


@router.post("/{tool_name}/test")
async def test_tool(tool_name: str):
    """
    Aracın çalışıp çalışmadığını test et
    
    Args:
        tool_name: Tool adı
        
    Returns:
        Test sonucu
    """
    
    logger.info(f"Testing tool: {tool_name}")
    
    # TODO: Tool'un --version veya --help komutunu çalıştır
    
    return {
        "tool": tool_name,
        "status": "working",
        "version": "1.0",
        "path": "/usr/bin/sqlmap"
    }
