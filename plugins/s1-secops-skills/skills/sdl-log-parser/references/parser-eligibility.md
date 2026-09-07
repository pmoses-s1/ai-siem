# Parser eligibility: when an SDL parser can be used at all

Read this before authoring anything. It decides whether an SDL parser is the right tool for a
source, or whether the work belongs in Data Pipeline Management (DPM).

## The rule

**The SDL parser sees exactly two attributes on an event: `message` and `parser`.**

- `parser` names which parser to apply. Its value is the parser name, matched against
  `/logParsers/<name>`.
- `message` is the content that parser is applied to.

Every other attribute on the event is invisible to the parser. It cannot read them, cannot filter
on them in a format string or a format-level `discard:`, and cannot use them as a `rewrites` input.
(They are visible to `mappings` predicates and `mappings` op `from:` paths, because mappings run
after parsing, but that is a post-parse stage and does not change which events the parser can act
on in the first place.)

## The four cases

| Case | `parser` | `message` | What happens | So do this |
|---|---|---|---|---|
| 1 | present | present | The SDL parser runs. The parser named by `parser` is applied to the content of `message`. | Author or edit `/logParsers/<parser>`. This is the normal path. |
| 2 | absent | present | The SDL parser cannot select a parser, so nothing runs. | Set a `parser` attribute on the event in DPM. Once DPM sets it, the SDL parser parses whatever is in `message` according to that parser name. Usually the cheapest fix, and the default recommendation. |
| 3 | absent | absent | The SDL parser cannot be used at all. | Parse in DPM instead. Do not author an SDL parser. |
| 4 | n/a | n/a | Logs already parsed in DPM. Events arrive pre-parsed with their fields already promoted; no SDL parser is involved. | Nothing to author here. Neither attribute needs to exist. |

Case 4 is a state, not a defect. A source that was parsed upstream is already queryable; the
absence of `parser` and `message` on it is expected and correct.

## The consequence that catches people out

**An SDL parser cannot reach fields that live outside `message`.** If someone is trying to write an
SDL parser against attributes that are already promoted to top level (an upstream collector or a
DPM pipeline flattened the event before it reached SDL), that is the wrong tool. No format string,
regex, or escaping trick fixes it, because the parser never sees those fields. The transformation
has to happen in DPM.

The tell is a parser that deploys cleanly, reports the right `metadata.version` on live events, and
still produces nothing: the root `attributes` block lands (proving the parser is running) while
every capture is null, because `message` is empty or holds something other than the text the format
strings were written against.

## How to determine which case a source is in

Inspect a sample event for the presence of `message` and `parser`. Anchor every query on a field
filter; a query that opens with a bare `*` returns HTTP 500.

Which anchor to use depends on how far the source has been onboarded:

- Normalised source: `dataSource.name='<SOURCE>'`.
- Un-normalised source (no `dataSource.name` yet): `serverHost='<HOST>'` or `parser='<PARSER_NAME>'`.
  Probe both; which one carries the data varies by source.

### 1. Look at a sample event

```text
dataSource.name='<SOURCE>' | columns timestamp, parser, message | sort -timestamp | limit 5
```

If both columns hold values, you are in case 1. If `parser` is blank and `message` holds raw text,
case 2. If both are blank while other fields are populated, case 3 or case 4 (case 4 is
distinguished by the event already carrying promoted, queryable fields).

### 2. Confirm with counts

A projection can mislead on a mixed stream, so count the populations. Use `field = *` for presence
and `!(field = *)` for absence. The parentheses are required: bare `!field` matches every row and
will report a source as entirely broken when it is fine.

Total events in the window:

```text
dataSource.name='<SOURCE>' | group events=count() | limit 1
```

Case 1, both present, broken out by parser name:

```text
dataSource.name='<SOURCE>' parser = * message = * | group events=count() by parser | sort -events | limit 20
```

Case 2, `message` present but `parser` absent:

```text
dataSource.name='<SOURCE>' message = * !(parser = *) | group events=count() | limit 1
```

Case 3, neither present:

```text
dataSource.name='<SOURCE>' !(message = *) !(parser = *) | group events=count() | limit 1
```

The three case counts plus any events with `parser` present and `message` absent should reconcile
to the total. If they do not, the anchor filter is wrong or the window differs between runs; fix
that before drawing a conclusion.

### Enumerating parser names across the tenant

When you do not yet know the source's parser name:

```text
parser = * | group events=count() by parser | sort -events | limit 200
```

Then pull a sample for the one you care about:

```text
parser='<PARSER_NAME>' | columns timestamp, parser, message | sort -timestamp | limit 20
```

A `parser` value with no `/logParsers/<name>` file behind it (a 404 from `sdl_get_file`) means the
sender tags events with that name but SDL has nothing to apply, so they ingest raw. That is still
case 1 for eligibility purposes: creating the file at that exact path normalises the live stream
going forward.

### PowerQuery syntax rules used above

Non-negotiable, and the reason these queries are written the way they are:

- Field presence is `field = *`.
- Field absence is `!(field = *)`, with the parentheses. Bare `!field` matches every row.
- Never open a query with a bare `*`; lead with a field filter such as `dataSource.name='X'`.
- Sort descending is `| sort -field`, never `sort field desc`.
- Use `| limit N`, never `| head N`.

## Case 2: setting the `parser` attribute from DPM

Case 2 is the common one and the cheapest to fix. The events already carry the raw text in
`message`; they are just missing the label that tells SDL which parser to apply. Nothing about the
payload needs to change.

In the DPM pipeline that delivers this source to SDL, set a `parser` attribute on the event whose
value is the parser name you intend to author or reuse, then deploy the pipeline. On the SDL side
this is the same binding the HEC `sourcetype` label produces: whatever names the parser on the way
in becomes the `parser` attribute SDL reads, and the parser at `/logParsers/<that name>` is applied
to `message`. Confirm the exact node and field name against the DPM console for the pipeline in
question rather than assuming a menu path.

Order of operations matters:

1. Pick the parser name. If the source already has a catalog parser, reuse that name.
2. Deploy `/logParsers/<name>` (or confirm it exists).
3. Set the `parser` attribute in DPM and deploy the pipeline.
4. Wait out parser activation, roughly 3 to 5 minutes, then confirm on the live stream that the
   new `metadata.version` appears and the expected fields are populated.

Parsers apply to newly ingested events only and SDL never re-parses history, so events that arrived
before the DPM change stay unparsed. Judge the fix on new events, not on the backlog.

## Case 3: neither attribute present

There is no SDL-side lever. The parser has no name to select and no content to act on, so parsing
has to happen in DPM. Tell the user that plainly rather than authoring a parser that cannot run,
and do not invent a parser name to attach to the source.

## Related

- `../SKILL.md`, *Gate 0*: the short decision table, hit before authoring.
- `../SKILL.md`, *Common gotchas*: the parser sees only `message` and `parser`; ingest-time
  attributes are invisible to formats and rewrites.
- `onboarding-learnings.md`: activation latency, account-level parser scope, sourcetype binding.
- `../../sdl-solutions/references/data-source-onboarding.md`, Step 0: the same gate as an
  onboarding step.
