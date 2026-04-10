#!/bin/sh
set -e
echo "Starting app, DB_PATH=${DB_PATH:-/data/scheduling.db}"
# Ensure /data directory exists (in case volume not yet mounted)
mkdir -p "$(dirname ${DB_PATH:-/data/scheduling.db})"
# Run as a quick Python snippet to init DB before gunicorn starts
python3 -c "
import os, sys
sys.path.insert(0, '/app')
os.environ.setdefault('DB_PATH', '/data/scheduling.db')
import app
app.init_db()
print('DB initialized at', app.DB_PATH)
"
exec gunicorn --bind "0.0.0.0:${PORT:-8080}" --workers 2 --timeout 120 app:app
