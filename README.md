# oci-vm-hunt

Retries creating an Oracle Cloud Always Free Ampere A1 VM until the region has capacity, then
disables its own workflow. Zero dependencies (Node 22, requests signed with `node:crypto`).

Each run: checks whether the named instance exists, creates the VCN / internet gateway / subnet if
missing, then tries the configured availability domain and the region's others, first at 2 OCPU /
12 GB (the 2026 Always Free allowance) and then at 1 OCPU / 6 GB. "Out of host capacity" and
throttling are a quiet retry; any other error fails the run.

Logs are public, so nothing identifying is printed. Configuration is repository secrets:
`OCI_TENANCY_OCID`, `OCI_USER_OCID`, `OCI_FINGERPRINT`, `OCI_PRIVATE_KEY` (an API signing key),
`OCI_IMAGE_OCID`, `OCI_SSH_PUBLIC_KEY`, optional `OCI_AVAILABILITY_DOMAIN`.
Optional env overrides: `OCI_REGION`, `OCI_OCPUS`, `OCI_MEMORY_GB`, `OCI_INSTANCE_NAME`,
`OCI_ASSIGN_PUBLIC_IP`, `OCI_TRY_ALL_DOMAINS`, `OCI_ALLOW_SMALLER`.

Scheduled workflows are paused by GitHub after 60 days without repository activity.
