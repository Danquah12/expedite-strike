import uuid
from datetime import datetime, timezone
from cyber_range.db.postgres import pg_connect


def create_scanner_run(scanner: str, target: str) -> str:
    """
    Creates a scanner run record and returns run_id (UUID).
    """
    run_id = str(uuid.uuid4())

    with pg_connect() as pg:
        with pg.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scanner_runs
                (id, scanner, target, started_at, status)
                VALUES (%s, %s, %s, %s, 'running')
                """,
                (run_id, scanner, target, datetime.now(timezone.utc)),
            )

    return run_id


def complete_scanner_run(run_id: str, status: str = "completed"):
    """
    Marks a scanner run as completed or failed.
    """
    with pg_connect() as pg:
        with pg.cursor() as cur:
            cur.execute(
                """
                UPDATE scanner_runs
                SET finished_at = now(),
                    status = %s
                WHERE id = %s
                """,
                (status, run_id),
            )
