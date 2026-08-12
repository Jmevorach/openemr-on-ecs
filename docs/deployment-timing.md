# Live E2E deployment timing

This report is generated from sanitized records produced by the guarded local live-E2E runner.
Durations are measurements, not estimates. Account IDs, resource ARNs, hostnames, and secrets are excluded.

No live E2E deployment has been approved or measured yet.


## Methodology

- A transparent Docker proxy records monotonic build durations without recording Docker arguments;
  asset publication is the serialized CDK asset-pipeline duration minus measured Docker builds.
- CDK deployment, post-deploy HTTPS wait, cleanup, and total durations use a local monotonic clock.
- Time to application readiness spans the CloudFormation stack creation timestamp through the first
  successful local HTTPS probe.
- CloudFormation stack, Aurora, ElastiCache, EFS, and ECS durations come from AWS API event timestamps.
- HTTPS readiness requires a successful TLS request with an HTTP 200 response containing OpenEMR.
- Deployment validation also checks expected stack resources, ECS desired count, target health, Aurora,
  and both EFS file systems.
- Cleanup timing includes stack deletion, owned orphan Lambda log-group cleanup, retained-asset
  inventory, and residual-resource inventory.

## Comparability caveats

Compare runs only when profile, Region, versions, and configuration fingerprint are compatible.
Bootstrap asset caching, AWS control-plane load, DNS and certificate propagation, account quota usage,
container-image caching, and file-asset packaging can materially affect durations. Failed and interrupted runs are not
included in successful timing aggregates.

## Source and reproduction

- Machine-readable history: `e2e-results/history.json`
- Runner guide: `LIVE-E2E.md`
- Regenerate this report without contacting AWS:

```bash
python -m tools.live_e2e report
```
