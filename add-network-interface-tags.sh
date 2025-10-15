#!/bin/bash

echo "add-network-interface-tags.sh"
for param in "$@"; do
  echo "Parameter: $param"
done

NAME=$1
NI_IDS=$2
ADDITIONAL_TAGS=$3

# 3. Loop through each network interface ID and apply the tags
for ni_id in $NI_IDS; do
    echo "Processing network interface ID: $ni_id"

    # Construct the base tags, including the dynamically generated 'Name' tag
    TAGS="Key=Name,Value=$NAME-${ni_id}"

    # Append any additional tags if they are defined
    if [ ! -z "$ADDITIONAL_TAGS" ]; then
        TAGS="${TAGS} ${ADDITIONAL_TAGS}"
    fi

    # 4. Use the AWS CLI 'create-tags' command to apply the tags
    # The --tags argument requires a specific format.
    echo "aws ec2 create-tags --resources $ni_id --tags $TAGS"
    aws ec2 create-tags --resources "$ni_id" --tags $TAGS
    echo "Tags applied successfully to $ni_id."
done
echo "Tagging process completed."