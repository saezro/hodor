# syntax=docker/dockerfile:1

FROM golang:1.27 AS builder
WORKDIR /src

ARG VERSION=dev
ENV CGO_ENABLED=0

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/hodor ./cmd/hodor

FROM gcr.io/distroless/static-debian12:nonroot

ENV HODOR_CONFIG=/etc/hodor/hodor.yaml

COPY --from=builder /out/hodor /hodor

EXPOSE 8080 8081
VOLUME ["/data"]

ENTRYPOINT ["/hodor", "serve"]
