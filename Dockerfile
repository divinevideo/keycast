# Build stage for Rust API
FROM rust:1.93-slim-bookworm AS rust-builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY ./api ./api
COPY ./signer ./signer
COPY ./core ./core
COPY ./keycast ./keycast
COPY ./cluster-hashring ./cluster-hashring
COPY ./tools ./tools
COPY ./database/migrations ./database/migrations
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock

RUN cargo build --release --features aws --bin keycast
RUN cargo build --release --example migrate-vine-users

# Build stage for Bun frontend
FROM oven/bun:1 AS web-builder

# Install build essentials for native modules
RUN apt-get update && apt-get install -y \
    python3 \
    python-is-python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Install node-gyp globally for native module builds
RUN bun add -g node-gyp

# VITE_DOMAIN and VITE_ALLOWED_PUBKEYS are now runtime environment variables
# They are injected into the HTML at runtime by the server

ENV NODE_OPTIONS="--max-old-space-size=2048"
ENV CI=true
ENV NODE_ENV=production
ENV VITE_BUILD_MODE=production
ENV PATH=/app/node_modules/.bin:$PATH
ENV VITE_DISABLE_CHUNK_SPLITTING=true
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

WORKDIR /app

# Copy keycast-login library (local dependency for web)
COPY ./keycast-login ./keycast-login

# Build keycast-login (dist/ is gitignored so we build it here)
WORKDIR /app/keycast-login
RUN bun install
RUN bun run build

# Copy web app
WORKDIR /app/web
COPY ./web .
COPY ./scripts ./scripts

# Install dependencies and build
RUN bun install

# Install ARM64-specific dependencies only on ARM64 architecture
RUN if [ "$(uname -m)" = "aarch64" ]; then \
    bun add -d @rollup/rollup-linux-arm64-gnu; \
    fi

# Generate SvelteKit configuration files (creates .svelte-kit directory)
RUN bunx svelte-kit sync

# Build (skip check in Docker - runs locally, but symlink resolution issues in Docker)
RUN bun run build

# Final stage
FROM debian:bookworm-slim AS runtime

# Kamal service label
LABEL service="keycast"
WORKDIR /app

# Kamal service label
LABEL service="keycast"

# Install only the essential runtime dependencies
RUN apt-get update && apt-get install -y \
    sqlite3 \
    ca-certificates \
    netcat-openbsd \
    bash \
    curl \
    unzip \
    iproute2 \
    procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Bun for use in the entrypoint script
RUN curl -fsSL https://bun.sh/install | bash

# Create necessary directories
RUN mkdir -p /app/database /data

# Copy built artifacts - keycast binary and migration tool
COPY --from=rust-builder /app/target/release/keycast ./
COPY --from=rust-builder /app/target/release/examples/migrate-vine-users ./
COPY --from=web-builder /app/web/build ./web
COPY --from=web-builder /app/web/package.json ./
COPY --from=web-builder /app/web/node_modules ./node_modules

# Copy ONLY database migrations (not the .db files)
COPY ./database/migrations ./database/migrations

# Copy example HTML files for testing
COPY ./examples ./examples

# Copy keycast-login IIFE bundle for examples
COPY --from=web-builder /app/keycast-login/dist ./keycast-login/dist

# Set environment variables
ENV NODE_ENV=production \
    BUN_ENV=production \
    PATH=/root/.bun/bin:$PATH \
    WEB_BUILD_DIR=/app/web

# Expose ports
EXPOSE 3000 5173

# Add a health check script
COPY scripts/healthcheck.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/healthcheck.sh

# Add an entrypoint script
COPY scripts/docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD ["/usr/local/bin/healthcheck.sh", "unified"]

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["unified"]
