"""ReconPro TUI Widgets — premium visual components.

Custom Textual widgets that make the dashboard feel alive:
    ScoreGauge         Animated Unicode arc gauge (0-100 score)
    Sparkline           Mini line chart using block characters
    StatCounter         Number with delta flash animation
    VelocityMeter       Real-time throughput bar (req/s, find/min)
    CommandCompleter    Fuzzy auto-complete dropdown for commands
    HintBar             Adaptive contextual hint strip
    ToastContainer      Stacked auto-dismissing notification toasts
"""

from .score_gauge import ScoreGauge
from .sparkline import Sparkline
from .stat_counter import StatCounter
from .velocity_meter import VelocityMeter
from .command_completer import CommandCompleter
from .hint_bar import HintBar
from .toast import ToastContainer

__all__ = [
    "ScoreGauge",
    "Sparkline",
    "StatCounter",
    "VelocityMeter",
    "CommandCompleter",
    "HintBar",
    "ToastContainer",
]
