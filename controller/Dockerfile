# Aegis-SRE Go action controller (Phase 5). Static binary, runs as non-root, no shell.
#   docker buildx build --platform linux/arm64 -f controller/Dockerfile \
#     -t aegis-controller:phase5 --output type=docker,dest=aegis-controller-phase5.tar controller/
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/aegis-controller .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/aegis-controller /aegis-controller
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/aegis-controller"]
