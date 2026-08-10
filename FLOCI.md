# Floci-backed live E2E emulation

This repository uses [Floci](https://github.com/floci-io/floci) to exercise the
live E2E AWS adapter and a mocked runner orchestration path without touching a
real AWS account.

Floci is **not** a substitute for an approved live AWS deployment. Real
`preflight` / `run` / `cleanup` against AWS remain local-only and require the
guards in [LIVE-E2E.md](LIVE-E2E.md).

## What CI covers

The `Floci Live E2E Emulation` job in `.github/workflows/ci.yml`:

1. Starts `floci/floci:1.6.0` through Testcontainers
2. Seeds STS identity, a dedicated Route 53 zone, CDK bootstrap stack, and
   bootstrap IAM roles
3. Runs `LiveE2EAws.preflight` against the emulator (service-quotas, IAM policy
   simulation, and emulator-unsupported read APIs such as EFS are Floci-emulated
   shims)
4. Verifies owned-stack cleanup refuses foreign ownership markers
5. Runs a mocked runner path for ownership/cleanup orchestration with CDK
   stubbed
6. Runs a real pinned-CDK smoke lifecycle against Floci (`tools/floci_cdk`):
   `cdk bootstrap` → `cdk deploy` → `cdk destroy`
7. Runs the **full guarded live E2E runner** against Floci: real bootstrap,
   OpenEMR E2E stack synth/diff/deploy through the pinned CDK CLI, emulated
   post-deploy validation, and owned-stack destroy

GitHub Actions never invokes `python -m tools.live_e2e preflight|run|cleanup`
as a workflow step; the Floci job drives the same runner through pytest.

## Local commands

```bash
.venv/bin/python -m pip install -r requirements.txt -r requirements-dev.txt
npm ci
pytest tests/tools/test_floci_emulator.py -q
pytest \
  tests/tools/test_floci_e2e.py \
  tests/tools/test_floci_cdk_deploy.py \
  tests/tools/test_floci_live_e2e_full.py \
  -m floci -q
```

Optional compose helper (usually unnecessary; tests start Floci themselves):

```bash
docker compose -f compose/docker-compose.floci.yml up
export OPENEMR_FLOCI_E2E=1
export OPENEMR_AWS_ENDPOINT_URL=http://127.0.0.1:4566
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
```

## Safety

- `OPENEMR_FLOCI_E2E=1` is required before CI signals are ignored
- The endpoint must be local (`localhost`, `127.0.0.1`, Docker bridge, `floci`)
- Real AWS hostnames are rejected
- Emulated mode never contacts `service-quotas`; write-permission simulation is
  replaced by IAM role existence checks after successful `AssumeRole`
- Emulator `UnknownOperationException` responses on read probes (for example EFS)
  are recorded as Floci-emulated passes instead of failing preflight

## Limits

The full Floci live E2E path deploys the real OpenEMR E2E stack through CDK.
Post-deploy validation is Floci-aware: it still requires CloudFormation
`CREATE_COMPLETE`, ownership markers, and the expected resource types, but it
does not require a publicly reachable OpenEMR HTTPS endpoint. Emulator gaps in
individual read APIs are reported as Floci-emulated passes.

Floci's IAM catalog does not include AWS Backup managed policies
(`AWSBackupServiceRolePolicyForBackup` / `...ForRestores`). When
`OPENEMR_FLOCI_E2E=1` is set, the runner synthesizes with
`live_e2e_emulated=true` so the Backup service role uses a disposable inline
policy instead of those AWS managed ARNs. Real AWS live E2E keeps the managed
policies.

If Floci cannot provision a required resource type, deploy fails and CI fails —
that is intentional. An explicitly approved live AWS run remains the fidelity
bar for production-like HTTPS, ECS health, and quota behavior.
