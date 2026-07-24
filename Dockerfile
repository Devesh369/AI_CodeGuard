FROM node:20-alpine

# Install Python3, pip, pylint, and bandit for local static scanning capabilities
RUN apk add --no-cache python3 py3-pip && \
    pip install --no-cache-dir --break-system-packages pylint bandit

WORKDIR /app

# Copy package management files
COPY package*.json ./

# Install npm dependencies
RUN npm ci --only=production

# Copy application source files
COPY . .

# Build production bundle
RUN npm run build

# Expose port 3000
EXPOSE 3000

# Set environment variables
ENV NODE_ENV=production
ENV PORT=3000

# Start production server
CMD ["npm", "start"]
