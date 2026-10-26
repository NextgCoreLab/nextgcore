# Base images are pinned by digest so a release is reproducible (#420). To bump: 
# `docker buildx imagetools inspect <tag>` and replace the digest.
FROM node:19@sha256:92f06fc13bcc09f1ddc51f6ebf1aa3d21a6532b74f076f224f188bc6b9317570

MAINTAINER Sukchan Lee <acetcom@gmail.com>

COPY webui /usr/src/nextgcore/webui

WORKDIR /usr/src/nextgcore/webui
RUN npm clean-install && \
    npm run build

ADD https://github.com/ufoscout/docker-compose-wait/releases/download/2.9.0/wait /wait
RUN chmod +x /wait

CMD /wait && npm run start

EXPOSE 9999
