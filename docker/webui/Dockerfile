FROM node:19

MAINTAINER Sukchan Lee <acetcom@gmail.com>

COPY webui /usr/src/nextgcore/webui

WORKDIR /usr/src/nextgcore/webui
RUN npm clean-install && \
    npm run build

ADD https://github.com/ufoscout/docker-compose-wait/releases/download/2.9.0/wait /wait
RUN chmod +x /wait

CMD /wait && npm run start

EXPOSE 9999
