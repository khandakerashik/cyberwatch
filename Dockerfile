FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    CYBERWATCH_DATA_DIR=/app/runtime

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10001 cyberwatch \
    && mkdir -p /app/runtime \
    && chown -R cyberwatch:cyberwatch /app/runtime

COPY --chown=cyberwatch:cyberwatch dist ./dist
COPY --chown=cyberwatch:cyberwatch data ./data
COPY --chown=cyberwatch:cyberwatch scripts ./scripts
COPY --chown=cyberwatch:cyberwatch server ./server

USER 10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8000')+'/healthz',timeout=3).read()"
CMD ["python", "-m", "server.app", "--host", "0.0.0.0"]
