# Counterexample fixture: hand-rolled header-token guard (no Depends). The
# handler declares an authorization Header and verifies the bearer token in
# its body — found during dogfooding on a one-shot migration endpoint.
# Must NOT fire.
from fastapi import APIRouter, Header, HTTPException
import os

router = APIRouter(prefix="/api/admin", tags=["admin-migrations"])


@router.post("/apply-migration")
async def apply_migration(file: str, authorization: str = Header(None)):
    expected_token = os.getenv("APPLY_MIGRATION_TOKEN", "").strip()
    if not expected_token:
        raise HTTPException(status_code=404, detail="Not Found")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    if token != expected_token:
        raise HTTPException(status_code=403, detail="Invalid token")
    return {"applied": file}
