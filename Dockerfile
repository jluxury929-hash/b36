# 1. Build Stage (Uses official image, bypassing download errors)
FROM rust:1.84-bookworm as builder

WORKDIR /app
COPY . .

# Build the release binary
RUN cargo build --release

# 2. Runtime Stage (Lightweight)
FROM debian:bookworm-slim

# Install SSL certs for HTTPS/RPC connections
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary from the builder
COPY --from=builder /app/target/release/apex_omega /app/apex_omega

# Run the bot
CMD ["./apex_omega"]
