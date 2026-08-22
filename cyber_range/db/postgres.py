import os
import psycopg2
from psycopg2.extras import RealDictCursor


def pg_connect():
    """
    Returns a new PostgreSQL connection.
    Uses environment variable PG_PASSWORD.
    """
    password = os.getenv("PG_PASSWORD")
    if not password:
        raise RuntimeError("PG_PASSWORD not set")

    return psycopg2.connect(
        dbname="vuln_intel",
        user="vuln_user",
        password=password,
        host="127.0.0.1",
        cursor_factory=RealDictCursor,
    )
