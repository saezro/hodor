# syntax=docker/dockerfile:1

FROM golang:1.27 AS builder
WORKDIR /src

ARG VERSION=dev
ENV CGO_ENABLED=0

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/hodor ./cmd/hodor
RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot

ENV HODOR_CONFIG=/data/hodor.yaml
ENV HODOR_DATA_DIR=/data

COPY --from=builder /out/hodor /hodor
COPY --from=builder --chown=65532:65532 /out/data /data

EXPOSE 8080 8081
VOLUME ["/data"]

ENTRYPOINT ["/hodor", "serve"]
