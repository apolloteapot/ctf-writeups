#!/bin/sh

set -e

sleep 10

echo "sleep done, initializing cortex"

python -m synapse.tools.modrole --add svcuser
python -m synapse.tools.modrole --allow 'node' svcuser
python -m synapse.tools.modrole --allow 'view.add' svcuser
python -m synapse.tools.moduser --add --passwd $PASSWORD --grant svcuser $USERNAME
python -m synapse.tools.storm cell:///vertex/storage "!runfile ./init_cortex.storm"