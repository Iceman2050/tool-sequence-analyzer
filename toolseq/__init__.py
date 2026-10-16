"""toolseq — detect privilege-escalation patterns across agent tool-call sequences."""
from .analyzer import analyze, load_events, load_tool_map, chain_to_mermaid

__all__ = ["analyze", "load_events", "load_tool_map", "chain_to_mermaid"]
__version__ = "1.0.0"
