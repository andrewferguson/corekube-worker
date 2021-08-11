# Comment: Image base with corekube worker installed
# Based upon ran_emulator/kubernetes/docker_slave/Dockerfile by github.com/j0lama

# Download ubuntu from the Docker Hub
FROM ubuntu:focal

# Install dependencies
RUN apt-get update
RUN apt-get -y install git libsctp-dev build-essential

# Extra dependencies for testing / debugging
RUN apt-get -y install python3 curl wget netcat screen libsctp1 lksctp-tools python3-pip nano

WORKDIR ../

# Install libck
# Bit of a hack - ideally this would be pulled from git but it's private
COPY libck/ libck/
WORKDIR libck/
RUN make
RUN make install

WORKDIR ../

# Install corekube_worker
COPY ./ corekube_worker/
WORKDIR corekube_worker/
RUN make
