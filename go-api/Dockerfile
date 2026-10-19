# syntax=docker/dockerfile:1
# Build context: repository root.
FROM golang:1.26-trixie AS build
WORKDIR /src
COPY go-api/go.mod go-api/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY go-api ./
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/go-api ./cmd/server

FROM gcr.io/distroless/static-debian13:nonroot
WORKDIR /app
COPY --from=build /out/go-api /app/go-api
COPY go-api/seed /app/seed
EXPOSE 8080
ENTRYPOINT ["/app/go-api"]
