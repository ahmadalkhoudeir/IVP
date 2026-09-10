"""Configuration loaded from environment variables (.env.example documents
every key). No real credentials belong here or in any committed file
(hard requirement 7) — only synthetic defaults for local/demo use.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    session_secret: str
    database_path: str
    confirmation_timeout: timedelta
    max_confirmation_attempts: int
    seed_demo_data: bool
    anchor_log_path: str


def load_settings() -> Settings:
    return Settings(
        session_secret=os.environ.get("IVP_SESSION_SECRET", "change-me-in-a-real-deployment"),
        database_path=os.environ.get("IVP_DATABASE_PATH", "./demo_data/ivp.db"),
        confirmation_timeout=timedelta(
            seconds=int(os.environ.get("IVP_CONFIRMATION_TIMEOUT_SECONDS", "240"))
        ),
        max_confirmation_attempts=int(os.environ.get("IVP_MAX_CONFIRMATION_ATTEMPTS", "3")),
        seed_demo_data=os.environ.get("IVP_SEED_DEMO_DATA", "true").lower() == "true",
        anchor_log_path=os.environ.get("IVP_ANCHOR_LOG_PATH", "./demo_data/anchor_log.jsonl"),
    )
