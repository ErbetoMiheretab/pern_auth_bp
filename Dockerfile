# Stage 1: Build/Dependency installation
FROM node:22-alpine

# 1. Install wget (and curl) explicitly for Healthchecks
# Alpine comes with a basic wget, but installing the full package is safer.
RUN apk add --no-cache wget curl

WORKDIR /app

# 2. Set ownership of the directory to the 'node' user
# This prevents permission errors when npm writes files
RUN chown -R node:node /app

# 3. Switch to the non-root user 'node'
USER node

# Copy package files (with correct ownership)
COPY --chown=node:node package*.json ./

# Install dependencies
RUN npm ci

# Copy the rest of the application code
COPY --chown=node:node . .

EXPOSE 4000

# Run the application
CMD ["npm", "start"]