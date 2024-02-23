FROM golang:latest

# Configure Go
ENV GOROOT /usr/lib/go
ENV GOPATH /go
ENV PATH /go/bin:$PATH

RUN mkdir -p ${GOPATH}/src ${GOPATH}/bin

WORKDIR $GOPATH

RUN curl -LO "https://vesio.azureedge.net/releases/vesctl/$(curl -s https://downloads.volterra.io/releases/vesctl/latest.txt)/vesctl.linux-amd64.gz"