#!/usr/bin/python3
import runpy
import sys
sys.argv = ["update-vuln-intel.py", "--days", "2", "--github-limit", "20", "--min-score", "45", "--quiet"]
runpy.run_path("/root/.hermes/scripts/update-vuln-intel.py", run_name="__main__")
