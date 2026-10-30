FROM python:3.14-alpine

WORKDIR /src

COPY requirements.txt setup.py MANIFEST.in ./
COPY gixy/ ./gixy/

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir --no-deps . \
    && adduser -D gixy

USER gixy

CMD ["gixy"]
