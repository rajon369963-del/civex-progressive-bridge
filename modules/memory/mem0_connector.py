"""
CIVEX Local Memory Connector - Mem0 Competitor Synthesis.
Local vectorless memory graph capturing entity relations and episodic state.
"""
import time
from typing import Dict, List, Any

class Mem0LocalConnector:
    def __init__(self):
        self.memories: List[Dict[str, Any]] = []

    def add_memory(self, user_id: str, text: str, metadata: Dict[str, Any] = None) -> str:
        mem_id = f"mem_{len(self.memories) + 1}_{int(time.time())}"
        entry = {
            "id": mem_id,
            "user_id": user_id,
            "text": text,
            "metadata": metadata or {},
            "timestamp": time.time()
        }
        self.memories.append(entry)
        return mem_id

    def query_memories(self, user_id: str, keyword: str = "") -> List[Dict[str, Any]]:
        return [
            m for m in self.memories
            if m["user_id"] == user_id and (not keyword or keyword.lower() in m["text"].lower())
        ]
