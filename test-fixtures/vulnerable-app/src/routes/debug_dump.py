# Fixture: diagnostic route, the class of endpoint dogfooding found in a real
# repo (/api/debug/raw-supabase-count queried user data with a service key and
# no auth). The unguarded one MUST fire.
from fastapi import APIRouter

router = APIRouter(prefix="/debug", tags=["debug"])


@router.get("/user-count")
async def debug_user_count():
    from db.supabase_client import supabase
    r = supabase.table("user_profiles").select("id", count="exact").limit(0).execute()
    return {"count": r.count}
