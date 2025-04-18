ARG BASE_IMAGE=alpine:3.19
# Final Docker image
FROM ${BASE_IMAGE} AS final-stage
LABEL MAINTAINER="Md Sulaiman <dev.sulaiman@icloud.com>"

RUN apk add --update --no-cache ca-certificates gcompat

# Create user fanal
RUN addgroup -S fanal && adduser -u 1234 -S fanal -G fanal
# must be numeric to work with Pod Security Policies:
# https://kubernetes.io/docs/concepts/policy/pod-security-policy/#users-and-groups
USER 1234

WORKDIR ${HOME}/app
COPY LICENSE .
COPY fanal .

EXPOSE 2801

ENTRYPOINT ["./fanal"]