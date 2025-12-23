# Stage 1: Build/Dependency installation
# Use a consistent node version
FROM node:22-alpine

WORKDIR /app

# Copy package files FIRST to leverage Docker layer caching
COPY package*.json ./

# Install ALL dependencies (including dev) — expected in dev
RUN npm ci

COPY . .


# Expose the port your app uses (adjust if needed)
EXPOSE 4000

# Run in development mode
CMD ["npm", "run", "dev:test"]