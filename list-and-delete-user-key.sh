#!/bin/bash

IAMUSER="jenkins"

echo "Listing all access keys for user: $IAMUSER"
aws iam list-access-keys --user-name "$IAMUSER"

echo "Checking for inactive keys..."
INACTIVEKEY=$(aws iam list-access-keys --user-name "$IAMUSER" \
  --query 'AccessKeyMetadata[?Status==`Inactive`].AccessKeyId' \
  --output text)

if [[ -n "$INACTIVEKEY" && "$INACTIVEKEY" != "None" ]]; then
  echo "Deleting inactive key(s): $INACTIVEKEY"
  for key in $INACTIVEKEY; do
    aws iam delete-access-key --user-name "$IAMUSER" --access-key-id "$key"
    echo "Deleted: $key"
  done
else
  echo "No inactive keys found."
fi
