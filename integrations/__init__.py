"""
Integrations Package.
Handles external clients for Elastic, Playbook RAG, and local Ollama model services.
"""
from .elastic_client import ElasticClient
from .playbook_retriever import PlaybookRetriever
from .ollama_client import OllamaClient

__all__ = ["ElasticClient", "PlaybookRetriever", "OllamaClient"]
