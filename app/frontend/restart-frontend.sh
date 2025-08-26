#!/bin/bash
echo "🔍 Encerrando qualquer processo na porta 5500..."
kill -9 $(lsof -t -i:5500) 2>/dev/null

echo "🚀 Subindo servidor HTTP na porta 5500..."
python3 -m http.server 5500
