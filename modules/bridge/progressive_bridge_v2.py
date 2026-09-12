"""
CIVEX Progressive Bridge v2 - Cross-Repo IPC and Glassmorphism Dashboard Bridge.
"""
from ..memory.mem0_connector import Mem0LocalConnector
from ..memory.khoj_fts5_bridge import KhojDesktopSearchBridge

class ProgressiveBridgeEngine:
    def __init__(self):
        self.memory = Mem0LocalConnector()
        self.search = KhojDesktopSearchBridge()

    def sync_event(self, event_type: str, payload: dict) -> dict:
        mem_id = self.memory.add_memory(user_id="rajon", text=f"[{event_type}] {payload.get('summary', '')}", metadata=payload)
        return {"status": "synchronized", "memory_id": mem_id}
