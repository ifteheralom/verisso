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

# Runtime image
FROM debian:bookworm-slim AS runtime
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app
# Copy the produced binary from builder
COPY --from=builder /app/target/release/as /app/as

# Use a non-root user (optional)
RUN useradd -m appuser && chown appuser:appuser /app/as
USER appuser

RUN chmod +x /app/as

EXPOSE 8001-8100
ENTRYPOINT ["/app/as"]