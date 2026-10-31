FROM python:3.14-alpine AS build

WORKDIR /src

COPY requirements-build.txt ./
RUN pip install --no-cache-dir --require-hashes --only-binary :all: -r requirements-build.txt

COPY setup.py MANIFEST.in ./
COPY gixy/ ./gixy/
RUN python -m build --wheel --no-isolation --outdir /dist

FROM python:3.14-alpine

COPY requirements.txt /tmp/
COPY --from=build /dist/ /tmp/dist/
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && pip install --no-cache-dir --no-deps /tmp/dist/*.whl \
    && rm -r /tmp/requirements.txt /tmp/dist \
    && adduser -D gixy

USER gixy

CMD ["gixy"]
