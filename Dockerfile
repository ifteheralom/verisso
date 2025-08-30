# Dockerfile: Ubuntu + Rust multi-stage build
# Usage:
#  docker build --build-arg BINARY=mybin -t myimage .
#  docker run --rm myimage

FROM rust:1.89 AS builder

WORKDIR /app

# Copy project files (adjust as needed)
COPY . .

# Build release (specify binary name with build-arg BINARY)
RUN cargo build --release --bin as
RUN cargo build --release --bin signer

# Runtime image
FROM debian:bookworm-slim AS runtime
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

RUN mkdir -p /app/op

# Copy the produced binary from builder
COPY --from=builder /app/target/release/as /app/as

COPY --from=builder /app/target/release/signer /app/signer

# Install necessary runtime dependencies
# RUN apt-get update && \
#     apt-get install -y --no-install-recommends \
#     ca-certificates \
#     libssl3 \
#     && rm -rf /var/lib/apt/lists/*

# Install ping untility
RUN apt-get update && \
    apt-get install -y --no-install-recommends iputils-ping && \
    rm -rf /var/lib/apt/lists/*

# Use a non-root user (optional)
RUN useradd -m appuser && chown appuser:appuser /app/as
RUN chown appuser:appuser /app/signer
USER appuser

RUN chmod +x /app/as
RUN chmod +x /app/signer

EXPOSE 8001-8100
# ENTRYPOINT ["/app/as"]
