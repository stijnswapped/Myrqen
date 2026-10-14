"""Invoice PDF downloads."""

import os

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from app.config import PDF_DIRECTORY
from app.security import get_current_user

router = APIRouter(prefix="/invoices")


@router.get("/{invoice_number}/pdf")
def invoice_pdf(invoice_number: str, user=Depends(get_current_user)):
    pdf_path = os.path.join(PDF_DIRECTORY, str(user.account_id), f"{invoice_number}.pdf")
    if not os.path.exists(pdf_path):
        raise HTTPException(status_code=404, detail="Invoice not found")
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"invoice-{os.path.basename(invoice_number)}.pdf",
    )
