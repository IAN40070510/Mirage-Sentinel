# Mirage-Sentinel 主容器 (FastAPI API Gateway + AI Agent)
FROM python:3.11-slim
RUN apt-get update && apt-get install -y gcc
# 避免 Python 緩衝輸出，可即時看到 log
ENV PYTHONUNBUFFERED=1

# 預設使用部署精簡依賴；若需完整訓練/研究依賴可在 build 時覆蓋。
ARG REQUIREMENTS_FILE=requirements.runtime.txt

WORKDIR /app

# 先複製依賴後安裝，加速 build cache
COPY requirements.txt requirements.runtime.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r ${REQUIREMENTS_FILE}

# 複製專案程式碼
COPY . .

# 若需支援 docker-in-docker（由 sandbox.py 使用 Docker CLI 隔離）
# 建議在 docker-compose volume mount /var/run/docker.sock: 才可使用

EXPOSE 8000

# 直接啟動 FastAPI（雲端平台優先使用 PORT，未提供時回退 8000）
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --log-level info"]
