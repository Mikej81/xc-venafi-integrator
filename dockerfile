FROM golang:latest

# Add Maintainer Info
LABEL maintainer="Michael Coleman"

# Configure Go
ENV GOROOT /usr/lib/go
ENV GOPATH /go
ENV PATH /go/bin:$PATH

RUN mkdir -p ${GOPATH}/src ${GOPATH}/bin && \
    go install -v golang.org/x/tools/gopls@latest && \
    go install -v golang.org/x/tools/cmd/goimports@latest

WORKDIR /app
COPY go.mod ./
COPY *.go ./

RUN curl -LO "https://vesio.azureedge.net/releases/vesctl/$(curl -s https://downloads.volterra.io/releases/vesctl/latest.txt)/vesctl.linux-amd64.gz"

CMD [ "entrypoint.sh" ]