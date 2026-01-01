# ==============================================================================
# Stage 1: Builder
# ==============================================================================
# Use node:20-slim (Debian) instead of Alpine for better native module compatibility
FROM node:20-slim AS builder

WORKDIR /app

# Install build tools required for compiling native modules like @roamhq/wrtc
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY package*.json ./
# Install all dependencies (including dev) for building and testing
RUN npm install

# Copy source code
COPY . .

# Build the project
RUN npm run build

# ==============================================================================
# Stage 2: Test Runner / Runtime
# ==============================================================================
FROM node:20-slim

WORKDIR /app

# Install runtime dependencies
# We need netcat-openbsd (nc) for the wait-for-it script and curl for health checks
RUN apt-get update && apt-get install -y \
    netcat-openbsd \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy everything from builder (includes source, dist, node_modules with devDeps)
COPY --from=builder /app ./ 

# Default environment variables for docker networking
ENV FREEBIRD_ISSUER_URL="http://freebird-issuer:8081"
ENV FREEBIRD_VERIFIER_URL="http://freebird-verifier:8082"
ENV WITNESS_GATEWAY_URL="http://witness-gateway:8080"
ENV HYPERTOKEN_RELAY_URL="ws://hypertoken-relay:3000"

# Default command runs the integration tests
CMD ["npm", "test"]