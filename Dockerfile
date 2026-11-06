# syntax=docker/dockerfile:1

FROM golang:1.27.3 AS builder
WORKDIR /app
# Cache dependencies to speed up builds
COPY go.* ./

#RUN go mod download
# Copy the Makefiles
COPY Makefile ./

# Copy the source code
COPY cmd/*.go cmd/
COPY *.go ./

# Build the application
RUN make build

FROM alpine:3.22
RUN addgroup -S app && adduser -S -G app app
USER app
WORKDIR /app
COPY --from=builder /app/bin/* .

ENTRYPOINT []
