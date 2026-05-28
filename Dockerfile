FROM node:20-alpine

# Install runtime dependencies
RUN apk add --no-cache \
    python3 \
    py3-pip \
    git \
    jq \
    curl \
    bash

# Install semgrep via pip
RUN pip3 install --no-cache-dir semgrep==1.104.0

# Set up working directory
WORKDIR /action

# Copy scanner source
COPY scanner/ ./scanner/
COPY semgrep-rules/ ./semgrep-rules/
COPY package.json yarn.lock ./

# Install Node dependencies
RUN yarn install --frozen-lockfile --production

# Entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
