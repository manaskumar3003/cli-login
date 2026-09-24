# ---- build ----
FROM golang:1.26-alpine AS build
WORKDIR /src

# Cache deps separately from source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/cli ./cmd/cli

# ---- test ----
FROM build AS test
CMD ["go", "test", "./..."]

# ---- run ----
FROM alpine:3.20
RUN adduser -D -h /home/app app
COPY --from=build /out/cli /usr/local/bin/cli
USER app
WORKDIR /home/app
ENTRYPOINT ["cli"]
