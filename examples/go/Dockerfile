# Build the standalone resource-server binary in a Go toolchain image,
# then copy just the binary into a minimal Alpine runtime image.

FROM golang:1.23-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 go build -o /out/rs ./cmd/rs

FROM alpine:3.20

RUN adduser -D -u 10001 app
USER app

COPY --from=build /out/rs /usr/local/bin/rs

ENV PORT=3000
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/rs"]
