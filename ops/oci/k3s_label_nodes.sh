#!/usr/bin/env bash
set -euo pipefail

app_node="${SENTINELA_APP_NODE:?set SENTINELA_APP_NODE to the control-plane node name}"
data_node="${SENTINELA_DATA_NODE:?set SENTINELA_DATA_NODE to the data worker node name}"
observability_node="${SENTINELA_OBS_NODE:?set SENTINELA_OBS_NODE to the observability worker node name}"

kubectl label node "$app_node" sentinela-role=app --overwrite
kubectl label node "$data_node" sentinela-role=data --overwrite
kubectl label node "$observability_node" sentinela-role=observability --overwrite

kubectl get nodes --show-labels
