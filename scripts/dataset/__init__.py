"""Dataset collectors. Each turns one public source into the same record shape.

A collector never invents a label. If a source does not state the CWE and
whether the sample is vulnerable, the sample is dropped - an inferred label is
indistinguishable from a wrong one once it is in the training set.
"""
from .record import Record, write_jsonl, read_jsonl        # noqa: F401
