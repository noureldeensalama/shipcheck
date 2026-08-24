# Fixture counterexample: guarded FastAPI route — should NOT fire.
from fastapi import APIRouter, Depends


def get_current_user():
    pass


router = APIRouter()


@router.get("/api/admin/invoices")
async def get_invoices(user=Depends(get_current_user)):
    return {"invoices": []}
