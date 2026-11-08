"""Tool descriptors, result models, argument builders, safe runner and host.

Tool-specific knowledge lives in the descriptors and argument builders — never
in the generic gateway — so policy and egress are data-driven and a tool cannot
be exposed without declaring its security-relevant behaviour.
"""

from __future__ import annotations
