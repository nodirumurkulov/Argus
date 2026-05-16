# ARGUS Report Schema

ARGUS JSON finding exports use schema version `1.0`.

## Top-Level Fields

- `schema_version`: Schema version for downstream consumers.
- `findings`: Array of finding objects.
- `summary`: Finding counts by severity.

## Finding Fields

- `id`: Stable ARGUS finding identifier.
- `title`: Short human-readable finding title.
- `severity`: One of `critical`, `high`, `medium`, `low`, or `info`.
- `category`: Finding category such as `ssh`, `network`, or `persistence`.
- `description`: Detailed finding explanation.
- `evidence`: Evidence strings collected during analysis.
- `recommendation`: Suggested remediation.
- `mitre`: MITRE ATT&CK technique IDs.
- `references`: External reference URLs.
- `llm_summary`: Optional generated summary.

## Summary Fields

- `total`: Total finding count.
- `critical`: Critical severity count.
- `high`: High severity count.
- `medium`: Medium severity count.
- `low`: Low severity count.
- `info`: Informational finding count.
