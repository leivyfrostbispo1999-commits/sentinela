#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
root_dir="$(pwd)"

execute=0
if [ "${1:-}" = "--execute" ]; then
  execute=1
fi

config_file="${OCI_CONFIG_FILE:-$HOME/.oci/config}"
compartment_id="${OCI_COMPARTMENT_ID:-}"
availability_domain="${OCI_AVAILABILITY_DOMAIN:-}"
subnet_id="${OCI_SUBNET_ID:-ocid1.subnet.oc1.sa-saopaulo-1.aaaaaaaaln7edugffsegjonsy776slps2xv7ojiesanjku3zsh64o7punpaa}"
display_name="${SENTINELA_A1_DISPLAY_NAME:-SENTINELA-ARM-HEAVY}"
shape_config="${SENTINELA_A1_SHAPE_CONFIG:-$root_dir/ops/oci/sentinela-arm-shape-1x6.json}"
source_details="${SENTINELA_A1_SOURCE_DETAILS:-$root_dir/ops/oci/sentinela-arm-source.json}"
metadata_file="${SENTINELA_A1_METADATA:-$root_dir/ops/oci/sentinela-arm-metadata.json}"
max_wait_seconds="${SENTINELA_A1_MAX_WAIT_SECONDS:-180}"

if [ ! -f "$config_file" ]; then
  echo "OCI config not found: $config_file" >&2
  echo "Set OCI_CONFIG_FILE to the operator config path." >&2
  exit 2
fi

if [ -z "$compartment_id" ]; then
  compartment_id="$(awk -F= '/^tenancy=/{print $2; exit}' "$config_file")"
fi

if [ -z "$compartment_id" ]; then
  echo "Unable to resolve compartment/tenancy OCID. Set OCI_COMPARTMENT_ID." >&2
  exit 2
fi

if [ -z "$availability_domain" ]; then
  availability_domain="$(oci --config-file "$config_file" iam availability-domain list \
    --compartment-id "$compartment_id" \
    --query 'data[0].name' \
    --raw-output)"
fi

echo "Ampere A1 isolated creation plan"
echo "  display-name: $display_name"
echo "  shape: VM.Standard.A1.Flex"
echo "  shape-config: $shape_config"
echo "  availability-domain: $availability_domain"
echo "  subnet-id: $subnet_id"
echo "  source-details: $source_details"
echo "  metadata: $metadata_file"
echo
echo "This script does not touch SENTINELA-AMD-TEST, Docker containers, volumes, DNS or Nginx."

if [ "$execute" -ne 1 ]; then
  echo
  echo "Dry run only. Re-run with --execute to request capacity from OCI."
  exit 0
fi

set +e
oci --config-file "$config_file" compute instance launch \
  --availability-domain "$availability_domain" \
  --compartment-id "$compartment_id" \
  --shape VM.Standard.A1.Flex \
  --shape-config "file://$shape_config" \
  --source-details "file://$source_details" \
  --subnet-id "$subnet_id" \
  --assign-public-ip true \
  --vnic-display-name sentinela-arm-vnic \
  --metadata "file://$metadata_file" \
  --display-name "$display_name" \
  --wait-for-state RUNNING \
  --max-wait-seconds "$max_wait_seconds"
status=$?
set -e

echo
echo "Current matching OCI instances:"
oci --config-file "$config_file" compute instance list \
  --compartment-id "$compartment_id" \
  --display-name "$display_name" \
  --all \
  --query 'data[].{name:"display-name",state:"lifecycle-state",shape:shape,id:id}' \
  --output table || true

if [ "$status" -ne 0 ]; then
  echo
  echo "Ampere A1 creation failed or timed out. Keep the AMD micro stack as the active 24/7 base."
  exit "$status"
fi

echo
echo "Ampere A1 instance is RUNNING. Bootstrap manually; do not migrate production automatically."
