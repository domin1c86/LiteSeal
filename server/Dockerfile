FROM rust:1-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY shared ./shared
COPY server ./server

RUN cargo build --release -p liteseal-server

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/liteseal-server /usr/local/bin/liteseal-server

ENV LITESEAL_BIND=0.0.0.0:3000
EXPOSE 3000

CMD ["liteseal-server"]
