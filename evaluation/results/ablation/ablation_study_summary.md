# Empirical Ablation Study: Component Breakdown & Reproducibility
**Generated:** 2026-11-14T11:08:51.154242+00:00  
**Evaluated Model:** `llama3:8b`  
**Telemetry Severity in Prompt:** `DISABLED (Pure Telemetry Reasoning)`  

| Configuration | Runs | Precision | Recall | F1-Score | Cohen's Kappa (κ) | Mean Time (MTTR) |
|---||---||---||---||---||---||---|
| Heuristic Baseline | 1 | 1.0000 ± 0.0000 | 0.7500 ± 0.0000 | 0.8571 ± 0.0000 | 0.7500 ± 0.0000 | 1.7 ± 0.0 ms |
| LLM Zero-Shot (No RAG, No Enrich) | 5 | 0.5000 ± 0.0000 | 1.0000 ± 0.0000 | 0.6667 ± 0.0000 | 0.0000 ± 0.0000 | 20660.6 ± 4130.0 ms |
| LLM + Stage 1 Enrich | 5 | 0.5000 ± 0.0000 | 1.0000 ± 0.0000 | 0.6667 ± 0.0000 | 0.0000 ± 0.0000 | 18759.3 ± 1700.6 ms |
| LLM + RAG Playbooks (No Enrich) | 5 | 0.5573 ± 0.0364 | 1.0000 ± 0.0000 | 0.7153 ± 0.0294 | 0.2000 ± 0.1118 | 27609.8 ± 6144.6 ms |
| Full Pipeline (Enrich + RAG) | 5 | 0.5209 ± 0.0317 | 1.0000 ± 0.0000 | 0.6846 ± 0.0270 | 0.0750 ± 0.1118 | 24050.6 ± 539.6 ms |
