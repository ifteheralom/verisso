# Dockerfile: Ubuntu + Rust multi-stage build
# Usage:
#  docker build --build-arg BINARY=mybin -t myimage .
#  docker run --rm myimage

FROM rust:1.89 AS builder

WORKDIR /app

# Copy project files (adjust as needed)
COPY . .

RUN cargo install --path .

# Build release (specify binary name with build-arg BINARY)
RUN cargo build --release --bin as
RUN cargo build --release --bin signer
RUN cargo build --release --bin bbs_sign

# Runtime image
FROM debian:bookworm-slim AS runtime
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

RUN mkdir -p /app/op

# Copy the produced binary from builder
COPY --from=builder /app/target/release/as /app/as
COPY --from=builder /app/target/release/signer /app/signer
COPY --from=builder /app/target/release/bbs_sign /app/bbs_sign

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
RUN chown appuser:appuser /app/bbs_sign
USER appuser

RUN chmod +x /app/as
RUN chmod +x /app/signer
RUN chmod +x /app/bbs_sign

EXPOSE 8001-8100
# ENTRYPOINT ["/app/as"]
