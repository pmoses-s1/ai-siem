# refusal-run: a deliberately-wrong artifact set for case 4

Case 4 (`strong-evidence-earns-confirmed`) is the one case in this suite that has to
*earn* a TRUE POSITIVE. Its two `output_matches` assertions once used the patterns
`(?i)\bconfirmed\b` and `(?i)true[ _-]positive`, which match the negations
"not confirmed" and "not a true positive", so a run that refused to call the verdict
still passed them.

`--self-check` cannot catch that: it grades every assertion against an EMPTY artifact
directory, so an assertion that matches a wrong-but-present answer looks falsifiable.
This directory is the wrong-but-present answer. Grade it with:

    python3 tools/run_evals.py --skill soc-investigator \
        --artifacts soc-investigator/evals/fixtures/refusal-run

Case 4 MUST fail. Every other case in the suite also fails here, because this fixture
only holds case 4's artifacts; that is expected.
