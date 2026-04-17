# Build stage
FROM golang:1.25-alpine AS builder

# Set the working directory
WORKDIR /app

# Copy go.mod and go.sum (if it exists)
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Ensure go.mod is synchronized with the source
RUN go mod tidy

# Build the application
# We use CGO_ENABLED=0 to ensure a static binary that runs on alpine/scratch
RUN CGO_ENABLED=0 GOOS=linux go build -o main ./cmd/server

# Run stage
FROM alpine:latest

# Set working directory
WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/main .

# Expose the application port
# Northflank uses the PORT environment variable
EXPOSE 8080

# Run the application
CMD ["./main"]
