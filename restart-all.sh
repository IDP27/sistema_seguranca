#!/bin/bash
# Script para reiniciar backend (FastAPI/uvicorn) e frontend (http.server)

# Configurações
BACKEND_PORT=8005
FRONTEND_PORT=5500
APP_PATH="app.main:app"
VENV_PATH=".venv"

echo "🔧 Reiniciando todo o sistema..."

# Ativa venv se existir
if [ -d "$VENV_PATH" ]; then
  echo "📦 Ativando venv em $VENV_PATH"
  source "$VENV_PATH/bin/activate"
fi

# --- Encerrar backend ---
echo "🛑 Encerrando backend na porta $BACKEND_PORT..."
kill -9 $(lsof -t -i:$BACKEND_PORT) 2>/dev/null

# --- Encerrar frontend ---
echo "🛑 Encerrando frontend na porta $FRONTEND_PORT..."
kill -9 $(lsof -t -i:$FRONTEND_PORT) 2>/dev/null

# --- Subir backend ---
echo "🚀 Subindo backend em http://127.0.0.1:$BACKEND_PORT ..."
uvicorn $APP_PATH --reload --port $BACKEND_PORT --host 127.0.0.1 &
BACK_PID=$!

# --- Subir frontend ---
echo "🌐 Subindo frontend em http://127.0.0.1:$FRONTEND_PORT ..."
python3 -m http.server $FRONTEND_PORT -d frontend &
FRONT_PID=$!

echo "✅ Sistema rodando!"
echo "   Backend PID: $BACK_PID"
echo "   Frontend PID: $FRONT_PID"
echo
echo "Para encerrar ambos, use:"
echo "   kill -9 $BACK_PID $FRONT_PID"
