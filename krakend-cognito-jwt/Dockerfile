FROM golang:1.23.7-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache gcc musl-dev

# Copy the Go module files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the plugin source code
COPY . .

# Build the plugin
RUN go build -buildmode=plugin -o krakend-cognito-jwt.so .