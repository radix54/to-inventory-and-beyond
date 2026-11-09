FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl golang libatomic1 make \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Makefile /app/Makefile
RUN make download-cdxgen
COPY . /app
RUN make cdxgen
ENTRYPOINT ["/app/cdxgen"]
