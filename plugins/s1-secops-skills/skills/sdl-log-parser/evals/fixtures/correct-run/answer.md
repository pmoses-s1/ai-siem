# AcmeMetrics: an SDL parser cannot run here

Do not deploy a parser for this source. The SDL parser sees exactly two attributes on an event,
`message` and `parser`. AcmeMetrics has neither, so the parser has no name to select and no
content to act on: it cannot be used at all, and there is no SDL-side lever. An SDL parser cannot
reach fields that live outside `message`, so the promoted top-level fields you can already query
are unreachable from any format string, rewrite, or escaping trick.

The transformation belongs in Data Pipeline Management (DPM). Extract `user` and `action` there.

One thing to rule out first: if AcmeMetrics is already pre-parsed in DPM, the missing `message`
and `parser` attributes are expected and correct rather than a defect, and there is nothing to
author on either side. I have not invented a parser name for the source.
