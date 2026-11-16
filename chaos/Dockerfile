FROM node:24-bookworm-slim AS dependencies

ENV PNPM_HOME=/pnpm
ENV COREPACK_HOME=/corepack
ENV PATH=/pnpm:$PATH

RUN corepack enable && corepack prepare pnpm@10.12.4 --activate
RUN apt-get update \
  && apt-get install -y --no-install-recommends build-essential python3 \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY patches ./patches
# Install against the complete workspace, including local pinned SDK archives.
# Copying selected manifests silently drops newly added workspace dependencies.
COPY apps ./apps
COPY packages ./packages
COPY test/artifacts ./test/artifacts
RUN pnpm install --frozen-lockfile

FROM node:24-bookworm-slim

ENV PNPM_HOME=/pnpm
ENV COREPACK_HOME=/corepack
ENV PATH=/pnpm:$PATH
ENV NODE_ENV=development

RUN corepack enable && corepack prepare pnpm@10.12.4 --activate \
  && chmod -R a+rX /corepack
WORKDIR /workspace
COPY --from=dependencies /workspace /workspace
COPY tsconfig.base.json tsconfig.json tsconfig.build.json vitest.config.ts ./

EXPOSE 8787 8008
HEALTHCHECK --interval=1s --timeout=2s --start-period=20s --retries=30 \
  CMD node -e "fetch('http://127.0.0.1:8787/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# Run node directly as PID 1 so SIGTERM reaches the daemon. pnpm and the tsx
# CLI are signal-forwarding wrappers; pnpm crashed with "kill EACCES" while
# forwarding, so graceful shutdown waited for Docker's SIGKILL.
CMD ["node", "--import", "tsx", "apps/chronologd/src/main.ts"]
