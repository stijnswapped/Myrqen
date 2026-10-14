"""Invoice PDF downloads."""

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from app.config import PDF_DIRECTORY
from app.security import get_current_user

router = APIRouter(prefix="/invoices")


@router.get("/{invoice_number}/pdf")
def invoice_pdf(invoice_number: str, user=Depends(get_current_user)):
    account_dir = (Path(PDF_DIRECTORY) / str(user.account_id)).resolve()
    pdf_path = (account_dir / f"{invoice_number}.pdf").resolve()
    if not pdf_path.is_relative_to(account_dir) or not pdf_path.exists():
        raise HTTPException(status_code=404, detail="Invoice not found")
    return FileResponse(pdf_path, media_type="application/pdf")
