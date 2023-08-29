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
                       wget

RUN wget https://nodejs.org/dist/v18.17.0/node-v18.17.0-linux-x64.tar.xz
RUN tar xvfJ node-v18.17.0-linux-x64.tar.xz
RUN cp -r node-v18.17.0-linux-x64/{bin,include,lib,share}  /usr/

RUN npm install -g solc