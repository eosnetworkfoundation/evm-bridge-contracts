FROM ubuntu:jammy
ENV TZ="America/New_York"
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y build-essential      \
                       cmake                \
                       gcc-11               \
                       g++-11               \
                       git                  \
                       jq                   \
                       wget                 \
                       xxd
