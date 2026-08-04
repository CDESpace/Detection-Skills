# Detection Skills

> Detection Skills is an open standard for the Agentic SOC, that transforms static detections into agentic workflows. Designed and used by Cyber Defense Engineers, it brings the best your team can do - to every alert.

This repo holds the Community Library for [Detection Skills](https://detectionskills.io)

Merged skills are published at the [Detection Skills Library](https://detectionskills.io).

## Contributing

Each skill is a directory under its type folder containing a `SKILL.md`:

```text
skills/
├── triage/
│   └── MFA Fatigue Baseline/
│       └── SKILL.md
├── investigation/
└── tuning/
```

```yaml
---
name: MFA Fatigue Baseline
description: Triage MFA push-bombing alerts to a verdict with evidence.
type: triage
version: 1.0.0
---
```

Name the directory after your skill — letters, digits, spaces and `()._-`. It sets
the skill's page address: `MFA Fatigue Baseline` is published at
[detectionskills.io/library/triage-mfa-fatigue](https://detectionskills.io/library/mfa-fatigue-baseline).

Required frontmatter: `name`, `description`, `type` (`triage` | `investigation` |
`tuning`), `version`. Optional: `metadata.author`, `metadata.labels`. Full format:
[detectionskills.io/specification](https://detectionskills.io/specification).


```sh
npm ci && npm run validate
```

Fifteen skill files per pull request, at most. `SKILL.md` is the only file published
today — other subfolders will be displayd in an upcoming version.

## License

[Apache-2.0](LICENSE)
