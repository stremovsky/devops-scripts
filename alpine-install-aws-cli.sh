#!/bin/sh

apk update

apk add --no-cache aws-cli

echo "aws sts get-caller-identity"
