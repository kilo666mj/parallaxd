FROM golang:1.26.5-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/parallaxd ./cmd/parallaxd && \
    CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/parallaxd-probe ./cmd/parallaxd-probe && \
    CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/parallaxd-watch ./cmd/parallaxd-watch

FROM alpine:3.22

RUN apk add --no-cache ca-certificates && \
    addgroup -S -g 65532 parallaxd && \
    adduser -S -D -H -u 65532 -G parallaxd parallaxd && \
    mkdir -p /var/lib/parallaxd && \
    chown parallaxd:parallaxd /var/lib/parallaxd
COPY --from=build /out/ /usr/local/bin/

USER parallaxd
ENTRYPOINT []
CMD ["parallaxd", "-config", "/demo/coordinator.json"]
