FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o dnscacheo ./cmd/server

FROM alpine:3.19
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/dnscacheo .
COPY --from=builder /app/config ./config

RUN mkdir -p /var/log/dnscacheo

EXPOSE 53/udp 53/tcp 853/tcp 443/tcp 8080/tcp

CMD ["./dnscacheo", "-config", "config/config.yaml"]
