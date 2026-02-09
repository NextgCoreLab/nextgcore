# NextGCore Network Function Image
# Extends core image, just adds the pre-built binary
#
# Build: docker build -f Dockerfile.nf \
#          --build-arg NF_NAME=nextgcore-amfd \
#          -t nextgcore-rust/amf:latest .

ARG CORE_IMAGE=nextgcore-core:latest
FROM ${CORE_IMAGE}

ARG NF_NAME=nextgcore-amfd

USER root

# Copy pre-built binary
COPY binaries/${NF_NAME} /usr/local/bin/${NF_NAME}

# Set permissions and create symlink
RUN chmod +x /usr/local/bin/${NF_NAME} && \
    chown nextgcore:nextgcore /usr/local/bin/${NF_NAME} && \
    ln -sf /usr/local/bin/${NF_NAME} /usr/local/bin/nf-binary

ENV NF_NAME=${NF_NAME}

USER nextgcore

ENTRYPOINT ["/usr/local/bin/nf-binary"]
CMD ["-c", "/etc/nextgcore/nf.yaml"]
