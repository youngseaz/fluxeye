"""路由注册 — 汇总所有 API 路由。"""

from fastapi import APIRouter

from app.api.traffic import router as traffic_router
from app.api.flows import router as flows_router
from app.api.ws import router as ws_router
from app.api.system import router as system_router
from app.api.capture import router as capture_router
from app.api.geo import router as geo_router
from app.api.ipfix import router as ipfix_router
from app.api.security import router as security_router
from app.api.profiles import router as profiles_router

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(traffic_router)
api_router.include_router(flows_router)
api_router.include_router(ws_router)
api_router.include_router(system_router)
api_router.include_router(capture_router)
api_router.include_router(geo_router)
api_router.include_router(ipfix_router)
api_router.include_router(security_router)
api_router.include_router(profiles_router)
