#!/usr/bin/env bash
# Regenerate or drift-check the import worker's fresh-seed manifest against a
# live TLS OpenEMR/MariaDB compose stack.
#
# Default mode rewrites tools/openemr-import-worker/fresh-seed-manifest.json
# from the compose-pinned OpenEMR image and verifies the worker's fresh-target
# policy against it. --check mode leaves the manifest untouched and fails when
# the checked-in manifest drifts from the pinned image (used by CI).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_DIR="${ROOT}/compose"
COMPOSE_FILE="docker-compose.test-ssl.yml"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-openemrseedci}"

MANIFEST="${ROOT}/tools/openemr-import-worker/fresh-seed-manifest.json"
WORKDIR="${SEED_MANIFEST_CI_WORKDIR:-${ROOT}/.seed-manifest-ci}"
LOG_DIR="${WORKDIR}/logs"
# Only MOUNT is handed to the importer uid; logs/ stays writable by the caller.
MOUNT="${WORKDIR}/work"
GENERATED="${MOUNT}/fresh-seed-manifest.json"
IMAGE="${IMPORT_WORKER_IMAGE:-openemr-import-worker:ci}"
IMAGE_PLATFORM="${IMPORT_WORKER_PLATFORM:-linux/arm64}"
OPENEMR_CONTAINER="${OPENEMR_CONTAINER:-openemr-container-test-ssl}"
MYSQL_CONTAINER="${MYSQL_CONTAINER:-mysql-test-ssl}"
WAIT_SECONDS="${IMPORT_CI_WAIT_SECONDS:-1200}"
MODE="write"

usage() {
  echo "Usage: $0 [--check]" >&2
  exit 2
}

while (($#)); do
  case "$1" in
    --check)
      MODE="check"
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      ;;
  esac
done

mkdir -p "${WORKDIR}" "${LOG_DIR}" "${MOUNT}"
chmod 700 "${WORKDIR}"

cleanup() {
  local status=$?
  set +e
  echo "Cleaning up compose stack (${COMPOSE_PROJECT_NAME})..."
  (
    cd "${COMPOSE_DIR}"
    docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans
  ) >"${LOG_DIR}/compose-down.log" 2>&1 || true
  exit "${status}"
}
trap cleanup EXIT

log() {
  printf '%s\n' "$*"
}

compose() {
  docker compose -f "${COMPOSE_FILE}" "$@"
}

# Make bind-mount paths writable by the importer user (uid 1000) without host sudo.
own_importer() {
  local path
  for path in "$@"; do
    docker run --rm --platform "${IMAGE_PLATFORM}" --user 0:0 --entrypoint chown \
      -v "${path}:${path}" \
      "${IMAGE}" \
      -R 1000:1000 "${path}"
  done
}

log "==> Building import worker image (${IMAGE})"
docker buildx build \
  --platform "${IMAGE_PLATFORM}" \
  --target ci \
  --load \
  --tag "${IMAGE}" \
  "${ROOT}/tools/openemr-import-worker"

log "==> Starting SSL compose stack"
cd "${COMPOSE_DIR}"
compose up -d

log "==> Waiting for MySQL TLS service"
for ((i = 1; i <= 60; i++)); do
  if compose logs mysql-test-ssl 2>/dev/null | grep -qiE 'ready for connections|mysqld.*ready'; then
    log "MySQL is ready"
    break
  fi
  if ((i == 60)); then
    compose logs mysql-test-ssl | tee "${LOG_DIR}/mysql.log"
    log "ERROR: MySQL failed to become ready"
    exit 1
  fi
  sleep 2
done

log "==> Waiting for OpenEMR bootstrap completion (up to ${WAIT_SECONDS}s)"
deadline=$((SECONDS + WAIT_SECONDS))
ready=0
while ((SECONDS < deadline)); do
  if docker exec "${OPENEMR_CONTAINER}" test -f /var/www/localhost/htdocs/openemr/sites/docker-completed 2>/dev/null; then
    log "Found sites/docker-completed"
    ready=1
    break
  fi
  if [[ "$(docker inspect -f '{{.State.Running}}' "${OPENEMR_CONTAINER}" 2>/dev/null || echo false)" != "true" ]]; then
    compose logs --tail=200 openemr-test-ssl | tee "${LOG_DIR}/openemr.log"
    log "ERROR: OpenEMR stopped before bootstrap completed"
    exit 1
  fi
  sleep 5
done
if ((ready != 1)); then
  compose logs --tail=200 openemr-test-ssl | tee "${LOG_DIR}/openemr.log"
  compose logs --tail=100 mysql-test-ssl | tee "${LOG_DIR}/mysql.log"
  log "ERROR: OpenEMR failed to initialize within ${WAIT_SECONDS}s"
  exit 1
fi

# Give openemr.sh a brief moment to finish key/material writes after the marker.
sleep 5

rm -f "${GENERATED}" "${MOUNT}/ca-cert.pem"
docker cp "${MYSQL_CONTAINER}:/mysql-ssl-certs/ca-cert.pem" "${MOUNT}/ca-cert.pem"
chmod 644 "${MOUNT}/ca-cert.pem"

NETWORK="$(docker inspect -f '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}}{{end}}' "${MYSQL_CONTAINER}")"
if [[ -z "${NETWORK}" ]]; then
  NETWORK="${COMPOSE_PROJECT_NAME}_openemr-test-network"
fi
log "Using docker network: ${NETWORK}"

# Ownership for the bind mount only — keep logs/ writable by the CI runner user.
own_importer "${MOUNT}"

log "==> Fingerprinting the live fresh-seed database"
docker run --rm \
  --platform "${IMAGE_PLATFORM}" \
  --user 1000:1000 \
  --network "${NETWORK}" \
  --entrypoint python \
  -e MYSQL_HOST=mysql-test-ssl \
  -e MYSQL_PORT=3306 \
  -e MYSQL_USERNAME=root \
  -e MYSQL_PASSWORD=testpass \
  -e MYSQL_DATABASE=openemr \
  -e MYSQL_SSL_CA=/work/ca-cert.pem \
  -v "${MOUNT}:/work" \
  "${IMAGE}" \
  /app/ci_update_seed_manifest.py --output /work/fresh-seed-manifest.json \
  | tee "${LOG_DIR}/generate.stdout"

if ! tail -n 1 "${LOG_DIR}/generate.stdout" | grep -q '"status": "passed"'; then
  log "ERROR: seed manifest generation failed"
  exit 1
fi

# The container runs as uid 1000; the caller usually does not.
if [[ ! -r "${GENERATED}" ]]; then
  log "ERROR: generated manifest is not readable by the caller"
  ls -l "${GENERATED}" || true
  exit 1
fi

if [[ "${MODE}" == "check" ]]; then
  log "==> Comparing generated manifest with the checked-in baseline"
  diff_status=0
  diff -u "${MANIFEST}" "${GENERATED}" >"${LOG_DIR}/manifest.diff" || diff_status=$?
  case "${diff_status}" in
    0)
      log "==> fresh-seed-manifest.json matches the pinned OpenEMR image"
      exit 0
      ;;
    1)
      cat "${LOG_DIR}/manifest.diff"
      log "ERROR: fresh-seed-manifest.json drifted from the pinned OpenEMR image; regenerate it with scripts/update-seed-manifest.sh"
      exit 1
      ;;
    *)
      log "ERROR: could not compare manifests (diff exited ${diff_status}); this is a harness failure, not drift"
      exit 1
      ;;
  esac
fi

cp "${GENERATED}" "${MANIFEST}"
log "==> Updated ${MANIFEST}"

log "==> Verifying the worker fresh-target policy against the new manifest"
docker run --rm \
  --platform "${IMAGE_PLATFORM}" \
  --user 1000:1000 \
  --network "${NETWORK}" \
  --entrypoint python \
  -e MYSQL_HOST=mysql-test-ssl \
  -e MYSQL_PORT=3306 \
  -e MYSQL_USERNAME=root \
  -e MYSQL_PASSWORD=testpass \
  -e MYSQL_DATABASE=openemr \
  -e MYSQL_SSL_CA=/work/ca-cert.pem \
  -v "${MOUNT}:/work:ro" \
  -v "${MANIFEST}:/app/fresh-seed-manifest.json:ro" \
  "${IMAGE}" \
  /app/ci_update_seed_manifest.py --verify \
  | tee "${LOG_DIR}/verify.stdout"

if ! tail -n 1 "${LOG_DIR}/verify.stdout" | grep -q '"status": "passed"'; then
  log "ERROR: seed manifest verification failed"
  exit 1
fi

log "==> Seed manifest update passed"
