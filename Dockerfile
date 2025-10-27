FROM rust:1.83-bookworm AS builder

WORKDIR /app
COPY . .

RUN cargo build --release --bin tameshi

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/tameshi /usr/local/bin/tameshi

ENTRYPOINT ["/usr/local/bin/tameshi"]
