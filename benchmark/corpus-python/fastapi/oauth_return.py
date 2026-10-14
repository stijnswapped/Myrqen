"""OAuth completion."""

from fastapi import APIRouter, Depends
from fastapi.responses import RedirectResponse

from app.security import complete_oauth

router = APIRouter(prefix="/oauth")


@router.get("/complete")
def oauth_complete(code: str, return_to: str = "/dashboard", session=Depends(complete_oauth)):
    session.exchange(code)
    return RedirectResponse(url=return_to, status_code=303)
