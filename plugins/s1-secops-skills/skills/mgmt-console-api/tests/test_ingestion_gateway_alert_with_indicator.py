"""Renamed to test_uam_alert_interface_single.py. This stub only exists
so historical invocations fail loudly with a clear pointer."""
import sys

# Guarded so `unittest discover` can import this module without the whole run
# aborting. A historical direct invocation still fails loudly, which is the
# behaviour this stub exists for.
if __name__ == "__main__":
    print("This test was renamed to test_uam_alert_interface_single.py.",
          file=sys.stderr)
    sys.exit(2)
