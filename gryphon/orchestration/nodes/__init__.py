"""Graph nodes.

Four modules, not seven. The four pipeline stages share one **data-driven**
stage node (``stage.py``) because the step table in ``constants`` already
describes what differs between them — the tool, the target source, the partial
result policy. Four near-identical modules whose only difference was a constant
would be four places for the stages to drift apart, and would make reordering a
code change instead of a data change.

What genuinely differs gets its own module: the authorization gate, target
admission, and report assembly.
"""

from __future__ import annotations

from gryphon.orchestration.nodes.gate import build_gate_node
from gryphon.orchestration.nodes.report import build_report_node
from gryphon.orchestration.nodes.stage import build_stage_node
from gryphon.orchestration.nodes.target_admit import build_target_admit_node

__all__ = [
    "build_gate_node",
    "build_stage_node",
    "build_target_admit_node",
    "build_report_node",
]
