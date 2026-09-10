FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

RUN useradd --system --uid 10001 guard \
    && mkdir -p /app/data \
    && chown -R guard:guard /app
USER guard

VOLUME ["/app/data"]
ENTRYPOINT ["aliyun-cdn-guard"]
CMD ["--config", "/app/config.yml"]

