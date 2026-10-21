FROM golang:1.26.4-alpine AS backend-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/hive ./cmd/hive

FROM alpine:3.22
RUN addgroup -S hive && adduser -S -G hive hive
WORKDIR /app
COPY --from=backend-build /out/hive /app/hive
RUN mkdir -p /app/data && chown -R hive:hive /app
USER hive
EXPOSE 2222 8080 3306 6379 8000
ENTRYPOINT ["/app/hive"]
