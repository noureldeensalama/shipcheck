# Fixture: FastAPI route, unguarded — should trip the detector.
from fastapi import APIRouter

router = APIRouter()


@router.get("/api/user/orders")
async def get_user_orders():
    return {"orders": ["order-1", "order-2"]}
