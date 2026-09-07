# AcmeGateway: why the parser edits change nothing

Events carry raw text in `message` but no `parser` attribute, so SDL has no parser name to
select and nothing runs. No edit to the parser file can change that.

1. Pick the parser name. Reuse the ai-siem catalog name if AcmeGateway already has one.
2. SDL side: deploy or confirm `/logParsers/acme_gateway`, with `metadata.version` bumped.
3. Pipeline side: set the `parser` attribute on the event in the Data Pipeline Management
   pipeline that delivers AcmeGateway to SDL, then deploy the pipeline.
4. Wait out parser activation, roughly 3 to 5 minutes.
5. Confirm on the live stream that the new `metadata.version` appears and the fields populate.

Parsers apply to newly ingested events only; SDL never re-parses history, so the backlog stays
unparsed. Judge the fix on new events, not on the backlog.
