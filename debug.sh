#!/usr/bin/env bash
# Rebuilds and (re)starts the SPM Project container so you can run or attach
# the Visual Studio debugger to it.
#
# Usage:
#   ./debug.sh                        # build + run + follow logs
#   ./debug.sh --no-logs              # build + run, return to the prompt
#   ./debug.sh --port 5000            # publish on localhost:5000 instead of 8080
#   ./debug.sh --configuration Release
#   ./debug.sh --stop                 # stop and remove the container

set -euo pipefail

CONFIGURATION="Debug"
PORT=8080
NO_LOGS=0
STOP=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--configuration)
            CONFIGURATION="$2"
            shift 2
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        --no-logs|-NoLogs)
            NO_LOGS=1
            shift
            ;;
        --stop|-Stop)
            STOP=1
            shift
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

NAME="spm-project"
IMAGE="spm-project:$(echo "$CONFIGURATION" | tr '[:upper:]' '[:lower:]')"

# Always run from the solution root (the Docker build context).
cd "$(dirname "${BASH_SOURCE[0]}")"

remove_old_container() {
    if [[ -n "$(docker ps -aq --filter "name=^${NAME}$")" ]]; then
        echo "Removing existing '${NAME}' container..."
        docker rm -f "$NAME" >/dev/null 2>&1 || true
    fi
}

if [[ "$STOP" -eq 1 ]]; then
    remove_old_container
    echo "Stopped."
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    echo "Error: Docker isn't running. Start Docker Desktop first." >&2
    exit 1
fi

echo "Building ${IMAGE}..."
docker build -f Application/Dockerfile --build-arg "BUILD_CONFIGURATION=${CONFIGURATION}" -t "$IMAGE" .

remove_old_container

echo "Starting container..."
docker run -d \
    --name "$NAME" \
    -p "${PORT}:8080" \
    -e ASPNETCORE_ENVIRONMENT=Development \
    "$IMAGE" >/dev/null

URL="http://localhost:${PORT}"
READY=0
for _ in $(seq 1 60); do
    STATE="$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null || echo "false")"
    if [[ "$STATE" != "true" ]]; then
        break
    fi
    if curl -s -o /dev/null --max-time 2 "$URL"; then
        READY=1
        break
    fi
    sleep 1
done

if [[ "$READY" -ne 1 ]]; then
    echo -e "\nThe app didn't come up. Last log lines:" >&2
    docker logs --tail 40 "$NAME"
    exit 1
fi

echo ""
echo "Ready:  ${URL}"
echo "Attach: Debug > Attach to Process > Docker (Linux Container) > '${NAME}' > dotnet"
echo "Stop:   ./debug.sh --stop"

if [[ "$NO_LOGS" -eq 0 ]]; then
    echo -e "\nFollowing logs (Ctrl+C to stop following; the container keeps running)...\n"
    docker logs -f --since 1s "$NAME"
fi
