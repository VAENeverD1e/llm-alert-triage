import pytest
from integrations.ollama_client import OllamaClient
from integrations.playbook_retriever import PlaybookRetriever


def test_ollama_client_offline_fallback():
    # Target port that won't connect immediately to test graceful fallback
    client = OllamaClient(base_url="http://localhost:11434", model_name="llama3:8b", timeout=1.0)
    assert isinstance(client.is_alive(), bool)
    
    # Text fallback
    resp = client.generate("test prompt", fallback_mock=True)
    assert resp is not None
    assert len(resp) > 0

    # JSON fallback
    json_resp = client.generate("test json prompt", json_format=True, fallback_mock=True)
    assert "decision" in json_resp
    assert "ESCALATE" in json_resp


def test_playbook_retriever_loading():
    retriever = PlaybookRetriever(playbooks_dir="./playbooks")
    
    # Test techniques mapped from real playbooks
    pb_lsass = retriever.get_playbook("T1003.001")
    assert pb_lsass is not None
    assert "LSASS Memory Dump" in pb_lsass

    pb_ps = retriever.get_playbook("T1059.001")
    assert pb_ps is not None
    assert "PowerShell" in pb_ps

    pb_net = retriever.get_playbook("T1046")
    assert pb_net is not None
    assert "Network Service Discovery" in pb_net

    # Test rule name lookup
    pb_by_rule = retriever.get_playbook("LSASS Memory Access")
    assert pb_by_rule is not None
    assert "T1003.001" in pb_by_rule
