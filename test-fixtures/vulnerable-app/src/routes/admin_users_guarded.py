# Fixture: admin router using a project-specific guard dependency name
# (`require_admin`) instead of the conventional `get_current_user`.
# The route clearly handles user data, so it MUST be recognized as guarded —
# found during dogfooding where every /admin/users route was flagged despite
# each handler taking `admin=Depends(require_admin)`.
from fastapi import APIRouter, Depends

from dependencies.admin_check import require_admin

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users")
async def list_users(
    admin=Depends(require_admin),
    page: int = 1,
):
    return {"users": [], "page": page}


@router.post("/users/{user_id}/reset-password")
async def reset_user_password(user_id: str, admin=Depends(require_admin)):
    return {"reset": user_id}
