FROM rustlang/rust:nightly-slim

# Install dependencies for building sqlx-cli and connecting to PostgreSQL
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Install sqlx-cli with only postgres feature (faster build)
RUN cargo install sqlx-cli --no-default-features --features postgres

WORKDIR /app

# Copy migrations directory
COPY migrations /app/migrations

# Default command runs migrations
CMD ["sqlx", "migrate", "run", "--source", "/app/migrations"]
