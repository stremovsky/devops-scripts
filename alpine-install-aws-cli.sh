#!/bin/sh

apk add --no-cache aws-cli

echo "aws sts get-caller-identity"
