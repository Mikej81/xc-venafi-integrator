FROM golang:latest

# Add Maintainer Info
LABEL maintainer="Michael Coleman"

# Configure Go
ENV GOUSER gouser
#ENV GOROOT /usr/lib/go
#ENV GOPATH /go
#ENV PATH /go/bin:$PATH

# Create a group and user
RUN useradd -s /bin/bash -m ${GOUSER} -g users

RUN go install -v golang.org/x/tools/gopls@latest && \
    go install -v golang.org/x/tools/cmd/goimports@latest

WORKDIR /${GOUSER}

COPY go.mod /${GOUSER}
COPY *.go /${GOUSER}

RUN apt update && apt install gzip && \
    curl -LO "https://vesio.azureedge.net/releases/vesctl/$(curl -s https://downloads.volterra.io/releases/vesctl/latest.txt)/vesctl.linux-amd64.gz" && \
    gzip -d vesctl.linux-amd64.gz && mv vesctl.linux-amd64 vesctl && chmod +x vesctl

USER ${GOUSER}

#CMD [ "entrypoint.sh" ]
CMD ["bash"]