"""GET /devices — list attached Android devices the pool can lease."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from sentinel.auth.jwt_auth import get_current_active_user
from sentinel.devices import get_device_manager

router = APIRouter(prefix="/devices", tags=["devices"])

# Module-scope manager — Redis-backed when SENTINEL_REDIS_URL is set,
# in-process otherwise. See sentinel/devices/redis_pool.py.
_manager = get_device_manager()


@router.get("")
async def list_devices(current_user=Depends(get_current_active_user)) -> JSONResponse:
    """Force a fresh `adb devices` enumeration and return what we see."""
    devs = await _manager.refresh()
    return JSONResponse(content=[d.to_dict() for d in devs])
