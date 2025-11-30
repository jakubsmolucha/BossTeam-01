import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any

DATA_PATH = Path(__file__).resolve().parent.parent / "data"
CONTACTS_FILE = DATA_PATH / "trusted_contacts.json"


def ensure_data_dir():
    DATA_PATH.mkdir(parents=True, exist_ok=True)


def load_contacts() -> List[Dict[str, Any]]:
    ensure_data_dir()
    if not CONTACTS_FILE.exists():
        return []
    try:
        return json.loads(CONTACTS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def save_contacts(contacts: List[Dict[str, Any]]):
    ensure_data_dir()
    CONTACTS_FILE.write_text(json.dumps(contacts, indent=2, ensure_ascii=False), encoding="utf-8")


def hash_safe_word(word: str) -> str:
    return hashlib.sha256((word or "").strip().lower().encode("utf-8")).hexdigest()


def verify_safe_word(stored_hash: str, attempt: str) -> bool:
    return stored_hash == hash_safe_word(attempt)
