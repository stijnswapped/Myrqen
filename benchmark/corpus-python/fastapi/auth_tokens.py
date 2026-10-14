"""Token issuance."""

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.security import OAuth2PasswordRequestForm

from app.security import authenticate, issue_tokens

router = APIRouter(prefix="/auth")


@router.post("/token")
def login(response: Response, form: OAuth2PasswordRequestForm = Depends()):
    user = authenticate(form.username, form.password)
    if user is None:
        raise HTTPException(401, detail="Bad credentials")
    access, refresh = issue_tokens(user)
    response.set_cookie("refresh_token", refresh, httponly=True, max_age=1209600, path="/auth")
    return {"access_token": access, "token_type": "bearer"}
