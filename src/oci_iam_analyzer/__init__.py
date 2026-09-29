"""Offline static review of OCI IAM policy statements."""
from .analysis import analyze
from .parser import parse_statement, load_export
__all__ = ["analyze", "parse_statement", "load_export"]
