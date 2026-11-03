FROM python:3.14-alpine3.24
RUN apk add --no-cache openssl ca-certificates
WORKDIR /app
COPY signer/service.py ./service.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8085
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c 'import os,urllib.request as u; r=u.Request("http://127.0.0.1:8085/internal/relay-sign",headers={"Authorization":"Bearer "+os.environ["PROFILE_SIGNER_TOKEN"]}); u.build_opener(u.ProxyHandler({})).open(r,timeout=8).read()'
CMD ["python", "service.py"]
