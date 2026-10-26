# Node.js subscriber-management WebUI (published as nextgcore-webui, #420).
#
# Node 22 LTS, pinned by digest so a release is reproducible. To bump:
# `docker buildx imagetools inspect node:22-bookworm-slim` and replace the digest.
#
# Runtime requirements (README "Two subscriber-management front ends ship"):
# SECRET_KEY and JWT_SECRET_KEY (each >= 32 characters, no fallback), DB_URI,
# and WEBUI_BIND_ADDR=0.0.0.0 to be reachable through a published port (the
# default is 127.0.0.1). There is no default account: create the first admin
# with `node server/bin/create-admin.js <username>`.
#
# Start ordering is the orchestrator's job (compose depends_on with a health
# condition); the image no longer downloads a wait binary at build time.
FROM node:22-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d

COPY webui /usr/src/nextgcore/webui

WORKDIR /usr/src/nextgcore/webui
RUN npm clean-install && \
    npm run build

USER node

CMD ["npm", "run", "start"]

EXPOSE 9999
