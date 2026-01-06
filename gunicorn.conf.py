# Gunicorn Configuration File for Production
# Usage: gunicorn -c gunicorn.conf.py server:app

import os
import multiprocessing

# Server Socket
bind = os.getenv('GUNICORN_BIND', '0.0.0.0:2000')
backlog = 2048

# Worker Processes
workers = int(os.getenv('GUNICORN_WORKERS', multiprocessing.cpu_count() * 2 + 1))
worker_class = 'sync'
worker_connections = 1000
timeout = 120
keepalive = 5

# Process Naming
proc_name = 'georgiabiz-api'

# Server Mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# Logging
errorlog = '-'  # stderr
loglevel = os.getenv('GUNICORN_LOG_LEVEL', 'info')
accesslog = '-'  # stdout
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# SSL (if not using reverse proxy)
# keyfile = '/path/to/keyfile'
# certfile = '/path/to/certfile'

# Hooks
def on_starting(server):
    print("🚀 Starting GeorgiaBiz Pro API Server...")

def on_reload(server):
    print("🔄 Reloading server...")

def worker_int(worker):
    print(f"⚠️ Worker {worker.pid} received INT or QUIT signal")

def worker_abort(worker):
    print(f"❌ Worker {worker.pid} was aborted")

