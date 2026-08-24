# Counterexample fixture: same debug-route shape as debug_dump.py but with a
# guard dependency. Must NOT fire.
from fastapi import APIRouter, Depends

from dependencies.admin_check import require_admin

router = APIRouter(prefix="/debug", tags=["debug"])


@router.get("/admin-source")
async def debug_admin_source(admin=Depends(require_admin)):
    return {"ok": True}
