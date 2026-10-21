# php-scan: looks for PHP (PHP2Shell) on a host and in its container image
# layers. Mount the host's / at /host; see README.md.
FROM --platform=$BUILDPLATFORM golang:1.26.4-alpine3.22@sha256:727cfc3c40be55cd1bc9a4a059406b28a059857e3be752aa9d09531e12c20c56 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod *.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags=-s -o /php-scan .

FROM scratch
LABEL org.opencontainers.image.source=https://github.com/rpendleton/php-scan \
      org.opencontainers.image.description="Inventories PHP on a host and in its container images, for PHP2Shell"
COPY --from=build /php-scan /usr/local/bin/php-scan
ENV PATH=/usr/local/bin
ENTRYPOINT ["php-scan"]
CMD ["/host"]
