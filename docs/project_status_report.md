# Báo cáo trung thực về trạng thái dự án LLM Alert Triage

> **Mục đích:** Tài liệu này tóm tắt đúng những gì đang có trong repository tại thời
> điểm viết báo cáo. Các con số benchmark cũ trong `docs/evaluation_results.md`
> đã được đánh dấu **invalidated** và không được dùng làm kết quả cuối cùng.

## 1. Mục tiêu dự án

Dự án xây dựng một hệ thống hỗ trợ SOC phân loại security alert từ SIEM theo hai
giai đoạn:

1. Chuẩn hóa alert và thu thập thêm ngữ cảnh kỹ thuật.
2. Đưa ngữ cảnh vào heuristic hoặc LLM để quyết định `Escalate`, `Close` hoặc
   `Unknown`, kèm reasoning, confidence và risk factors.

Phạm vi telemetry hiện tại tập trung vào:

- Windows Sysmon.
- Suricata IDS.
- Alert được chuẩn hóa từ dữ liệu Elastic/Kibana.

## 2. Những phần đã triển khai

### 2.1. Chuẩn hóa schema

`NormalizedAlert` trong `agent/schemas/triage_schema.py` cung cấp envelope chung
và các context block tùy chọn:

- `ProcessContext`.
- `RegistryContext`.
- `NetworkContext`.

Hàm `NormalizedAlert.from_raw_alert()` xử lý một số khác biệt giữa field dạng
dotted của Kibana và object ECS lồng nhau, đồng thời có fallback cho một số
sub-technique MITRE bị thiếu trong raw alert.

### 2.2. Pipeline hai giai đoạn

`TriageOrchestrator` điều phối:

1. **Fact-Finding:** thu thập process, network và thông tin enrichment.
2. **Verdict:** dùng playbook RAG + Ollama nếu có, hoặc heuristic fallback nếu
   LLM không khả dụng.

Pipeline có schema Pydantic cho input/output và xử lý lỗi theo hướng fail-safe:
pipeline error mặc định tạo verdict `Escalate` với confidence thấp hơn để SOC
biết rằng có lỗi thực thi.

### 2.3. Elasticsearch enrichment

`integrations/elastic_client.py` và `agent/fact_finding/collector.py` hỗ trợ
hai loại enrichment chính:

- Tìm parent process cho một số Sysmon event nếu alert không chứa sẵn parent.
- Suy ra hostname từ IP đối với Suricata alert nếu thiếu `host.name`.

Enrichment không lấy dataset benchmark mới. Benchmark vẫn replay các JSON có sẵn;
Elastic chỉ bổ sung context khi được cấu hình và truy cập được.

### 2.4. RAG playbook

`integrations/playbook_retriever.py` đọc các playbook MITRE trong `playbooks/`
và cung cấp hướng dẫn TP/FP cho Verdict Agent. Đây là retrieval cục bộ từ file,
không phải vector database hay hệ thống Graph RAG.

### 2.5. LLM inference

`integrations/ollama_client.py` cung cấp interface tới Ollama, với model mặc định
được cấu hình là `llama3:8b`. LLM được dùng ở Stage 2 để sinh verdict JSON.

**Chưa có LLM fact-finding hoàn chỉnh:** Stage 1 hiện vẫn là logic Python tĩnh.
Tham số `ollama_client` có mặt trong `FactFindingAgent`, nhưng collector chưa
thực hiện ReAct/tool-calling hay một lượt suy luận LLM độc lập.

### 2.6. Prompt-injection defense

`agent/security/prompt_guard.py` sanitize một số field và phát hiện pattern prompt
injection trước khi đưa alert vào pipeline. Nếu phát hiện injection, pipeline bổ
sung bằng chứng và ép verdict sang `Escalate` nếu LLM trả `Close`.

Đây là defense dựa trên pattern/sanitization, chưa phải bằng chứng rằng hệ thống
chống được mọi prompt injection trong môi trường thực tế.

### 2.7. API và thông báo

Repository có:

- FastAPI webhook gateway trong `api/`.
- FIFO background worker để xử lý tuần tự.
- Authentication bằng webhook secret.
- Discord forwarder cho notification.
- Endpoint health/results theo README.

Bug entrypoint dùng `settings.api_host`/`settings.api_port` đã được sửa thành
`settings.host`/`settings.port`.

### 2.8. Confidence policy

Verdict Agent hiện có policy dùng hai ngưỡng:

- `Escalate`: `0.70`.
- `Close`: `0.85`.

Nếu confidence thấp hơn ngưỡng tương ứng, verdict được chuyển thành `Unknown`
để human review. Đây là policy routing, **không phải confidence calibration theo
logit hoặc xác suất đã hiệu chuẩn**.

### 2.9. Evaluation harness

`evaluation/replay_harness.py` hỗ trợ:

- Heuristic baseline.
- LLM không RAG.
- LLM + RAG.
- Multi-run benchmark.
- Ablation suite.
- Metrics gồm precision, recall, F1, latency và Cohen's kappa.

Dataset hiện tại có 16 scenario:

- 8 attack.
- 8 benign.

Các scenario bao phủ một số kỹ thuật MITRE như LSASS access, port scan, scheduled
task, DLL injection, PowerShell, C2/network connection và Run Key.

Trong thay đổi gần đây, benchmark mặc định khử một số label leakage:

- Bỏ `reason`.
- Chuẩn hóa host/user.
- Chuẩn hóa IP.
- Bỏ Suricata signature/category giả ở benchmark.

Prompt verdict cũng không còn đưa `Detection Reason` hoặc Suricata signature/category
vào LLM prompt.

## 3. Những gì đã kiểm thử

Đã chạy và đạt:

- `5 passed` cho `tests/test_replay_harness.py`.
- `31 passed` cho nhóm regression gồm:
  - `tests/test_fact_finding_enrichment.py`.
  - `tests/test_agent_schema.py`.
  - `tests/test_prompt_injection.py`.
- Python compilation cho các package chính đã thành công.
- Test hồi quy mới xác nhận benchmark sanitizer loại bỏ reason, identity, IP và
  signature/category dễ lộ nhãn.
- Test thủ công xác nhận confidence dưới ngưỡng được chuyển thành `Unknown`.

**Chưa có cơ sở để nói toàn bộ test suite đã pass trong phiên làm việc này.**

## 4. Những phần chưa làm được hoặc chưa chứng minh được

### 4.1. Chưa có kết quả benchmark LLM mới hợp lệ

Kết quả LLM cũ trong `evaluation/results/eval_llm_rag_latest.json` được tạo trước
các thay đổi về severity, sanitization và label leakage. Vì vậy không được dùng
để kết luận recall, precision, F1 hoặc MTTR hiện tại.

Cần chạy lại sau khi dataset/prompt mới ổn định:

- Comparative benchmark.
- Multi-run.
- Full ablation.
- Có và không có enrichment.

Tại thời điểm viết tài liệu này, `evaluation/results/ablation/` mới có artifact
heuristic của lần chạy đang/đã bắt đầu; chưa có bảng ablation hoàn chỉnh để trích
dẫn.

### 4.2. Enrichment chưa được chứng minh trong benchmark hoàn chỉnh

Harness đã có đường truyền `ELASTIC_URL` vào orchestrator. Tuy nhiên:

- Elasticsearch phải reachable.
- `.env` không nên được coi là bằng chứng benchmark đã dùng enrichment.
- Cần kiểm tra artifact kết quả có `enrichment_configured: true`.
- Nếu chạy không có Elastic, kết quả chỉ là replay trên JSON tĩnh.

Benchmark không bật Kibana UI và không tự lấy alert mới từ Kibana.

### 4.3. Fact-Finding chưa phải LLM agent/tool-calling

Stage 1 chưa có:

- LLM reasoning riêng.
- ReAct loop.
- Tool registry/calling protocol.
- Điều tra nhiều bước tự động.
- Threat-intelligence lookup.
- Active Directory privilege lookup.
- IP reputation lookup.

### 4.4. Unknown chưa được đánh giá thực nghiệm

Code đã có `Unknown` routing theo confidence threshold, nhưng chưa có một benchmark
được thiết kế riêng để đo:

- Tần suất `Unknown`.
- Độ chính xác của việc chuyển human review.
- Calibration error.
- Trade-off giữa false escalation và false close.

### 4.5. Prompt-injection benchmark chưa phải LLM benchmark đầy đủ

Các kết quả prompt-injection cũ không đủ để chứng minh ASR/defense effectiveness
trong LLM thực tế nếu chúng chạy bằng heuristic hoặc payload đơn giản. Cần chạy
lại với:

- LLM thật.
- Payload đa dạng và che giấu.
- Kiểm tra output trước/sau guard.
- Báo cáo riêng từng mode và model.

### 4.6. Dataset nhỏ và có nguy cơ circular evaluation

N = 16 là dataset nhỏ. Benign scenarios được tạo thủ công và playbook có nhiều
điều kiện tương ứng với các scenario đó. Do đó kết quả có thể phản ánh việc
playbook khớp với dataset hơn là năng lực tổng quát hóa trong SOC thực tế.

Dataset cũng chưa có:

- Nhiều host/user/network distribution tự nhiên.
- Train/test split độc lập.
- Nhiều alert cùng kỹ thuật nhưng khác biến thể.
- Human-annotated inter-rater ground truth.

### 4.7. Heuristic baseline còn đơn giản

Heuristic baseline hiện chủ yếu dựa vào severity, anomalous parent process và
injection evidence. Nó chưa tương đương một detection/correlation engine thực tế
như Sigma/EQL/SPL đầy đủ. Vì vậy không nên tuyên bố LLM vượt trội hơn mọi
rule-based SOC system dựa trên baseline này.

### 4.8. Một số field và cấu hình chưa được thực thi đầy đủ

Các giới hạn sau vẫn còn:

- `context_window_minutes` chưa được dùng đầy đủ trong collector.
- `max_events_per_alert` chưa được thực thi như một giới hạn truy vấn tổng quát.
- Chưa có CloudTrail/GuardDuty parser.
- Chưa có AWS telemetry support trong `NormalizedAlert`.
- Chưa có threat intelligence hoặc AD integration.
- Chưa triển khai tight-vs-loose Kibana rule evaluation đúng nghĩa.
- Chưa có model comparison thực nghiệm với model thứ hai.

## 5. Các tuyên bố không nên đưa vào báo cáo như sự thật hiện tại

Không nên tuyên bố nếu chưa có artifact benchmark mới:

- “LLM đạt recall 100%”.
- “LLM không bỏ sót breach nào”.
- “MTTR là 0.41 ms hoặc 40.4 giây”.
- “Prompt injection ASR = 0%”.
- “Enrichment đã được kiểm thử trong benchmark”.
- “Fact-Finding là LLM agent có tool-calling”.
- “Hệ thống đã sẵn sàng production”.

Các câu trên hoặc dựa vào kết quả cũ đã invalidated, hoặc vượt quá những gì code
hiện tại thực sự chứng minh.

## 7. Việc cần làm tiếp theo

1. Đợi ablation hiện tại hoàn tất hoặc dừng nếu Ollama/Elastic bị treo.
2. Kiểm tra output có `label_leakage_sanitized: true`.
3. Nếu muốn đánh giá enrichment, chạy với Elasticsearch reachable và kiểm tra
   `enrichment_configured: true`.
4. Chạy lại multi-run và ablation sau khi xác nhận dataset/prompt không còn leakage.
5. Cập nhật `docs/evaluation_results.md` bằng artifact mới, không copy số liệu cũ.
6. Nếu cần tuyên bố về prompt injection, chạy riêng LLM-based injection suite với
   payload đa dạng.
