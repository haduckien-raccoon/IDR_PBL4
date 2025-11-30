from fastapi import APIRouter
from . import ai, alerts, dashboard, response, rules, analytics,view_ai, view_log,incident, ws, edit_reverse_proxy, apache_log_ws, block_ip

api_router = APIRouter()
# api_router.include_router(ai.router)
api_router.include_router(alerts.router)
api_router.include_router(dashboard.router)
# api_router.include_router(response.router)
api_router.include_router(rules.router)
api_router.include_router(analytics.router)
api_router.include_router(view_ai.router)
api_router.include_router(view_log.router)
api_router.include_router(incident.router)
api_router.include_router(ws.router)
api_router.include_router(edit_reverse_proxy.router)
api_router.include_router(apache_log_ws.router)
api_router.include_router(block_ip.router)
