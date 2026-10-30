FROM python:3.14-alpine

WORKDIR /src

COPY setup.py MANIFEST.in ./
COPY gixy/ ./gixy/

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir . \
    && adduser -D gixy

USER gixy

CMD ["gixy"]
