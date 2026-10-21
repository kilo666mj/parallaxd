FROM golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS build

RUN apk add --no-cache --upgrade ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/parallaxd ./cmd/parallaxd && \
    CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/parallaxd-probe ./cmd/parallaxd-probe && \
    CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/parallaxd-watch ./cmd/parallaxd-watch && \
    CGO_ENABLED=0 go build -buildvcs=false -trimpath -o /out/parallaxd-healthcheck ./cmd/parallaxd-healthcheck
RUN mkdir -p /out/data && chown 65532:65532 /out/data

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/parallaxd /parallaxd
COPY --from=build /out/parallaxd-probe /parallaxd-probe
COPY --from=build /out/parallaxd-watch /parallaxd-watch
COPY --from=build /out/parallaxd-healthcheck /parallaxd-healthcheck
COPY --from=build --chown=65532:65532 /out/data /var/lib/parallaxd

USER 65532:65532
ENTRYPOINT []
CMD ["/parallaxd", "-config", "/demo/coordinator.json"]
