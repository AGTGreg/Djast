#!/usr/bin/env python3
"""Generate unique secrets for dev.env. Run once after project creation, then delete."""
import re
import secrets
from pathlib import Path

dev_env = Path(__file__).parent / "dev.env"
content = dev_env.read_text()

content = re.sub(
    r'SECRET_KEY="GENERATE_ME"',
    f'SECRET_KEY="{secrets.token_urlsafe(50)}"',
    content,
)

db_password = secrets.token_urlsafe(24)

content = re.sub(
    r'DB_PASSWORD="GENERATE_ME"',
    f'DB_PASSWORD="{db_password}"',
    content,
)

content = re.sub(
    r'POSTGRES_PASSWORD="GENERATE_ME"',
    f'POSTGRES_PASSWORD="{db_password}"',
    content,
)

dev_env.write_text(content)
