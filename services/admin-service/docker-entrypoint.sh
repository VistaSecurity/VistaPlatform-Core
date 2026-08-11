#!/bin/sh
set -e

# Container starts as appuser (non-root). Upload directories are pre-created
# in the image with correct ownership. For volume mounts, configure fsGroup
# in the Kubernetes pod security context instead of relying on runtime chown.
exec "$@"
