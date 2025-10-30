# Multi-stage Dockerfile to produce a static Go binary
FROM golang:1.25-alpine AS builder
WORKDIR /src

# Copy source and build static binary
COPY . .
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64
RUN go build -trimpath -ldflags="-s -w" -o /app ./...

# Final minimal image
FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app /app
EXPOSE 9000
ENTRYPOINT ["/app"]