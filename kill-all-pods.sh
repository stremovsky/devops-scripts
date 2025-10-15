#!/bin/bash

kubectl get pods -A -n argocd | grep ecr-credentials-sync | awk '{print $1, $2}' | xargs -n2 sh -c 'kubectl delete pod -n $0 $1'
