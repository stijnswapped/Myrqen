"""Static configuration for the shop API."""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = str(BASE_DIR / "data")

# Signs partner callback payloads.
PARTNER_SIGNING_SECRET = "mqcanary-4c81e0b97a2d4f65b3e19a07c58d2f61"

PARTNER_HOSTS = frozenset({"127.0.0.1:5030", "partner.example.test"})
