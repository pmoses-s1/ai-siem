# Ingestion patterns (moved)

Direct SDL ingestion (`uploadLogs`, `addEvents`) has been removed from this skill. Ingest raw logs/events via the **event collector** on the ingest host (`/services/collector/raw` and `/event`, with a named `parser`), authenticated with an SDL Log Write Key in `S1_HEC_TOKEN`. UAM alert creation lives in `mgmt-console-api` (`uam_*`) and keeps using the console API token. This skill covers queries and configuration files only.
