#!/bin/bash

echo "🔥 Starting Auto Pentest Tool..."

# -------------------------------
# CONFIG
# -------------------------------
ZAP_PORT=8080
BACKEND_PORT=8000
FRONTEND_PORT=8501
BASE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LOG_DIR="$BASE_DIR/logs"
VENV_DIR="$BASE_DIR/venv"

mkdir -p "$LOG_DIR"

# -------------------------------
# COLORS
# -------------------------------
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
RESET='\033[0m'

ok()   { echo -e "${GREEN}[+]${RESET} $1"; }
warn() { echo -e "${YELLOW}[!]${RESET} $1"; }
fail() { echo -e "${RED}[✖]${RESET} $1"; }

# -------------------------------
# CLEANUP FUNCTION
# -------------------------------
cleanup() {
    echo ""
    echo "🛑 Stopping Auto Pentest Tool..."
    [ -n "$ZAP_PID" ]      && kill $ZAP_PID      2>/dev/null && ok "ZAP stopped"
    [ -n "$BACKEND_PID" ]  && kill $BACKEND_PID  2>/dev/null && ok "Backend stopped"
    [ -n "$FRONTEND_PID" ] && kill $FRONTEND_PID 2>/dev/null && ok "Frontend stopped"
    echo "✅ All services stopped."
    exit 0
}

trap cleanup SIGINT SIGTERM

# -------------------------------
# FREE PORT FUNCTION
# -------------------------------
free_port() {
    local PORT=$1
    local PID
    PID=$(lsof -ti :"$PORT" 2>/dev/null)
    if [ -n "$PID" ]; then
        warn "Port $PORT in use (PID $PID) → killing..."
        kill -9 "$PID" 2>/dev/null
        sleep 1
    fi
}

# -------------------------------
# CHECK PYTHON
# -------------------------------
echo ""
ok "Checking Python..."

if ! command -v python3 &>/dev/null; then
    fail "python3 not found. Install Python 3.8+ and retry."
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
ok "Python $PY_VER found"

# -------------------------------
# CHECK PROJECT FILES
# -------------------------------
ok "Checking project structure..."

MISSING=0
for f in main.py app.py reports/generator.py reports/template.html reports/__init__.py; do
    if [ ! -f "$BASE_DIR/$f" ]; then
        fail "Missing: $f"
        MISSING=1
    fi
done

if [ "$MISSING" -eq 1 ]; then
    fail "One or more required files are missing. Expected structure:"
    echo ""
    echo "  auto-pentest-tool/"
    echo "  ├── main.py"
    echo "  ├── app.py"
    echo "  ├── requirements.txt"
    echo "  ├── run.sh"
    echo "  └── reports/"
    echo "      ├── __init__.py"
    echo "      ├── generator.py"
    echo "      └── template.html"
    echo ""
    exit 1
fi

ok "All project files found"

# -------------------------------
# VIRTUAL ENVIRONMENT
# -------------------------------
ok "Setting up virtual environment..."

# Use existing 'env' folder if user already has one
if [ -d "$BASE_DIR/env" ] && [ -f "$BASE_DIR/env/bin/activate" ]; then
    VENV_DIR="$BASE_DIR/env"
    ok "Found existing 'env' virtual environment"
elif [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    ok "Virtual environment created at venv/"
else
    ok "Virtual environment already exists — skipping"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
ok "Virtual environment activated"

# -------------------------------
# INSTALL DEPENDENCIES
# -------------------------------
ok "Installing dependencies..."

if [ -f "$BASE_DIR/requirements.txt" ]; then
    pip install --upgrade pip --quiet
    pip install -r "$BASE_DIR/requirements.txt" --quiet
    ok "Dependencies installed"
else
    warn "requirements.txt not found — skipping pip install"
fi

# -------------------------------
# CHECK EXTERNAL TOOLS
# -------------------------------
ok "Checking external tools..."

for tool in nuclei nikto; do
    if command -v "$tool" &>/dev/null; then
        ok "$tool found"
    else
        warn "$tool not found — $tool scans will be skipped at runtime"
    fi
done

ZAP_CMD=""
for candidate in zap.sh zaproxy zap; do
    if command -v "$candidate" &>/dev/null; then
        ZAP_CMD="$candidate"
        ok "ZAP found → $ZAP_CMD"
        break
    fi
done

if [ -z "$ZAP_CMD" ]; then
    warn "ZAP not found on PATH — ZAP scans will be skipped"
fi

# -------------------------------
# FREE PORTS
# -------------------------------
ok "Freeing ports..."
free_port $ZAP_PORT
free_port $BACKEND_PORT
free_port $FRONTEND_PORT

# -------------------------------
# START ZAP
# -------------------------------
if [ -n "$ZAP_CMD" ]; then
    echo ""
    ok "Starting ZAP on port $ZAP_PORT..."

    "$ZAP_CMD" -daemon -port $ZAP_PORT -config api.disablekey=true \
        > "$LOG_DIR/zap.log" 2>&1 &
    ZAP_PID=$!

    ok "Waiting for ZAP to initialize (25s)..."
    sleep 25

    if ! kill -0 $ZAP_PID 2>/dev/null; then
        fail "ZAP failed to start. Check $LOG_DIR/zap.log"
        exit 1
    fi
    ok "ZAP is running (PID $ZAP_PID)"
else
    warn "Skipping ZAP startup — not installed"
    ZAP_PID=""
fi

# -------------------------------
# START BACKEND (FLASK)
# -------------------------------
echo ""
ok "Starting Backend on port $BACKEND_PORT..."

PYTHONPATH="$BASE_DIR" python3 "$BASE_DIR/main.py" \
    > "$LOG_DIR/backend.log" 2>&1 &
BACKEND_PID=$!

ok "Waiting for backend to be ready..."
BACKEND_READY=0
for i in {1..10}; do
    sleep 2
    if curl -s "http://127.0.0.1:$BACKEND_PORT/health" >/dev/null 2>&1; then
        ok "Backend is ready ✅"
        BACKEND_READY=1
        break
    fi
    echo "    [...] Attempt $i/10 — waiting..."
done

if [ "$BACKEND_READY" -eq 0 ]; then
    fail "Backend did not become ready. Check $LOG_DIR/backend.log"
    echo ""
    cat "$LOG_DIR/backend.log"
    cleanup
    exit 1
fi

if ! kill -0 $BACKEND_PID 2>/dev/null; then
    fail "Backend stopped unexpectedly. Check $LOG_DIR/backend.log"
    exit 1
fi

# -------------------------------
# START FRONTEND (STREAMLIT)
# -------------------------------
echo ""
ok "Starting Frontend on port $FRONTEND_PORT..."

export STREAMLIT_BROWSER_GATHER_USAGE_STATS=false
export STREAMLIT_SERVER_HEADLESS=true

streamlit run "$BASE_DIR/app.py" \
    --server.port $FRONTEND_PORT \
    --server.address 0.0.0.0 \
    --browser.gatherUsageStats false \
    --server.headless true \
    > "$LOG_DIR/frontend.log" 2>&1 &
FRONTEND_PID=$!

sleep 5

if ! kill -0 $FRONTEND_PID 2>/dev/null; then
    fail "Frontend failed to start. Check $LOG_DIR/frontend.log"
    echo ""
    cat "$LOG_DIR/frontend.log"
    cleanup
    exit 1
fi

ok "Frontend is running (PID $FRONTEND_PID)"

# -------------------------------
# OPEN BROWSER
# -------------------------------
URL="http://127.0.0.1:$FRONTEND_PORT"
ok "Opening browser..."

if command -v xdg-open &>/dev/null; then
    xdg-open "$URL" 2>/dev/null &
elif command -v open &>/dev/null; then
    open "$URL" 2>/dev/null &
else
    warn "Could not auto-open browser. Open manually: $URL"
fi

# -------------------------------
# STATUS BANNER
# -------------------------------
echo ""
echo "--------------------------------------"
echo "✅  Auto Pentest Tool is Running"
echo "🌐  UI:       $URL"
echo "⚙️   Backend:  http://127.0.0.1:$BACKEND_PORT"
echo "🛡   ZAP:      http://127.0.0.1:$ZAP_PORT"
echo "📂  Logs:     $LOG_DIR/"
echo "Press CTRL+C to stop everything"
echo "--------------------------------------"
echo ""

# -------------------------------
# MONITOR LOOP
# -------------------------------
while true; do
    sleep 3

    if [ -n "$ZAP_PID" ] && ! kill -0 $ZAP_PID 2>/dev/null; then
        fail "ZAP stopped unexpectedly. Check $LOG_DIR/zap.log"
        cleanup
    fi

    if ! kill -0 $BACKEND_PID 2>/dev/null; then
        fail "Backend stopped unexpectedly. Check $LOG_DIR/backend.log"
        cleanup
    fi

    if ! kill -0 $FRONTEND_PID 2>/dev/null; then
        fail "Frontend stopped unexpectedly. Check $LOG_DIR/frontend.log"
        cleanup
    fi

done
