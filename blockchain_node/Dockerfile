# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy dependency files and source code
COPY go.mod ./
COPY main.go ./
COPY dashboard.html ./

# Build statically linked binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o angad-blockchain main.go

# Production runtime stage
FROM alpine:3.20

# Install ca-certificates and curl for healthchecks
RUN apk --no-cache add ca-certificates curl tzdata

WORKDIR /app

# Create directory for persistent blockchain data
RUN mkdir -p /app/data

# Copy compiled binary from builder stage
COPY --from=builder /app/angad-blockchain /app/angad-blockchain

# Environment defaults
ENV PORT=8080
ENV CHAIN_FILE=/app/data/chain.json

# Expose HTTP port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Run the node
ENTRYPOINT ["/app/angad-blockchain"]
