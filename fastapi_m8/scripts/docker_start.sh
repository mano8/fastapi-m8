#!/usr/bin/env bash
# Wait for the database and then start uvicorn.
# Usage: CMD ["bash", "/app/fastapi_m8/scripts/docker_start.sh"]
set -e

python -m fastapi_m8.scripts.pre_start

exec uvicorn app.main:app --host 0.0.0.0 --port 8000 "$@"
