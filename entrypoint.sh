#!/usr/bin/env bash

./vesctl request secrets get-public-key > /certs/xc-api-pubkey
./vesctl request secrets get-policy-document --namespace shared --name ves-io-allow-volterra > xc-api-policy

go run .