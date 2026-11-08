# Phân Tích Chuyên Sâu & Giải Thích Các Điểm Yếu Của Dự Án LLM Alert Triage

Tài liệu này giải thích chi tiết, minh bạch bản chất kỹ thuật, rủi ro học thuật/thực tế và hướng khắc phục cho 5 nhóm vấn đề còn tồn đọng trong dự án **LLM Alert Triage**.

---

## 📑 Mục Lục
1. [Nhóm A: Đánh Giá Chưa Đủ Sức Thuyết Phục (Methodology & Empirical Weaknesses)](#nhóm-a-đánh-giá-chưa-đủ-sức-thuyết-phục)
2. [Nhóm B: Hallucination Của LLM Bị Diễn Giải Sai Thành "Thận Trọng"](#nhóm-b-hallucination-của-llm-bị-diễn-giải-sai-thành-thận-trọng)
3. [Nhóm C: Kiến Trúc Lệch So Với Proposal (Architectural Deviations)](#nhóm-c-kiến-trúc-lệch-so-với-proposal)
4. [Nhóm D: Prompt Injection – Kết Quả 0% ASR Chưa Phản Ánh Thực Tế](#nhóm-d-prompt-injection--kết-quả-0-asr-chưa-phản-ánh-thực-tế)
5. [Nhóm E: Chất Lượng Repo, Mã Nguồn Rác & Mâu Thuẫn Dữ Liệu](#nhóm-e-chất-lượng-repo-mã-nguồn-rác--mâu-thuẫn-dữ-liệu)
6. [Kế Hoạch Khắc Phục Khả Thi Trước Khi Bảo Vệ](#kế-hoạch-khắc-phục-khả-thi-trước-khi-bảo-vệ)

---

## Nhóm A: Đánh Giá Chưa Đủ Sức Thuyết Phục

### 1. Kích thước tập đánh giá quá nhỏ (N = 16) và thiếu phương sai thống kê
* **Hiện trạng kỹ thuật:**
  * File `data/ground_truth.jsonl` chỉ chứa đúng **16 kịch bản** (8 alert tấn công, 8 alert lành tính).
  * Bộ harness (`evaluation/replay_harness.py`) chỉ chạy đúng **1 lần** cho mỗi mode (`heuristic`, `llm_rag`).
* **Tại sao đây là điểm yếu nghiêm trọng?**
  * Trong thống kê và ML, $N=16$ là tập mẫu đồ chơi (toy dataset). Khi tập tấn công chỉ có $N=8$, chỉ cần **1 mẫu sai** là Recall rớt ngay từ $100\%$ ($8/8$) xuống $87.5\%$ ($7/8$). Điểm số Recall $1.0000$ vì thế mang tính may rủi rất cao.
  * LLM bản chất là mô hình sinh ngẫu nhiên (dù đặt `temperature: 0.1` thì output token vẫn có dao động). Việc chạy 1 lần không đo được **độ lệch chuẩn (standard deviation)** hay **khoảng tin cậy 95% (confidence interval)**. Hội đồng học thuật sẽ đánh giá kết quả thiếu giá trị chứng minh thực nghiệm.

### 2. Nguy cơ Circular Evaluation (Vòng lặp đóng & Data Leakage)
* **Hiện trạng kỹ thuật:**
  * Các kịch bản tấn công (`data/attack_scenarios/`) được export từ chính lab mà bạn vừa dựng và vừa chạy các bài test Atomic Red Team.
  * Các kịch bản benign (`data/benign_scenarios/`) được tạo thủ công bằng tay.
  * Các tiêu chí phân loại False Positive trong playbooks (`playbooks/PB-*.md`) được viết sao cho **khớp từng chi tiết** với dữ liệu benign:
    * `BNG-T1003.001`: playbook ghi đúng `access_mask: 0x1410` và `CallTrace` có `cimwin32.dll`.
    * `BNG-T1053.005`: playbook ghi đúng tiến trình tạo là `GoogleUpdate.exe` trong `Program Files`.
    * `BNG-T1547.001`: playbook ghi đúng `ms-teams.exe`.
* **Tại sao đây là điểm yếu?**
  * Đây là lỗi "học tủ / học vẹt" (data leakage / dataset contamination). Bạn là người viết test, người tạo log benign, và cũng là người soạn playbook để LLM đọc. Việc LLM đối chiếu và ra kết quả đúng 6/8 trường hợp benign thực chất là đọc chép lại điều kiện mà bạn đã mớm sẵn, không phản ánh khả năng phân tích trong môi trường thực tế khi gặp log lạ.

### 3. Thiên kiến định dạng (Format Confounding) và "Lối tắt" Severity/Risk Score
* **Hiện trạng kỹ thuật:**
  * File **Attack** là log Kibana SIEM nguyên bản (`_source`, nested ECS, `severity: high`, `risk_score: 73`).
  * File **Benign** là JSON tự tổng hợp với schema phẳng (`severity: low`, `risk_score: 20-25`), không đi qua parser `from_raw_alert()`.
  * Trong prompt của Stage 2 (`agent/verdict/evaluator.py`, dòng 158):
    ```text
    - Severity: {alert.severity} (Risk Score: {alert.risk_score})
    ```
* **Tại sao đây là điểm yếu?**
  * LLM rất nhạy bén với các "shortcut". Vì 100% attack có severity `high`/`critical` và risk score $>70$, còn 100% benign có severity `low` và risk score $\le 25$, LLM chỉ cần nhìn 2 con số này là ra quyết định mà **không cần đọc các trường kỹ thuật khác** (như command line, call trace, network packet). Khi đó bài kiểm tra năng lực hiểu an ninh mạng của LLM bị biến tướng thành một phép so sánh số học đơn giản.

### 4. Baseline Heuristic bị biến thành "người rơm" (Strawman Baseline)
* **Hiện trạng kỹ thuật:**
  * Trong hàm `_evaluate_heuristic()` (`agent/verdict/evaluator.py`, dòng 302-307):
    ```python
    is_suspicious = (
        alert.severity.lower() in ["high", "critical"]
        or facts.has_anomalous_parent_process
        or has_injection
    )
    decision = TriageDecision.ESCALATE if is_suspicious else TriageDecision.CLOSE
    ```
* **Tại sao đây là điểm yếu?**
  * Trong các hệ thống SOC thực tế, các rule-only correlation engine (như Sigma, Splunk SPL, Elastic EQL) chứa hàng chục điều kiện chi tiết về đường dẫn, tham số, tài khoản loại trừ, port mạng.
  * Việc bạn viết một rule baseline chỉ gồm 2 dòng kiểm tra severity và parent process rồi tuyên bố "LLM vượt trội hơn heuristic rule 25% recall" là so sánh khập khiễng (ngụy biện Strawman), hạ thấp rule-based để tôn LLM lên.

### 5. Thiếu độ tin cậy đánh giá (Metrics, Judges, Ablation)
* **Hiện trạng:**
  * Chỉ số **Cohen's Kappa ($\kappa$)** trong bảng so sánh (`0.75`) thực tế chỉ là đo giữa kết quả pipeline với nhãn ground truth do chính bạn gán. Đó không phải là Cohen's Kappa giữa **chuyên viên SOC con người** và **Agent** (Inter-Annotator Agreement).
  * Chỉ số **MTTR** (Mean Time to Respond) được ghi là `40,422 ms (40.4s)`. Thực tế đây chỉ là thời gian chờ Ollama sinh token (Inference Latency), hoàn toàn không phải chỉ số MTTR nghiệp vụ SOC (vốn đo từ khi phát hiện tới khi đóng ticket).
  * Chưa chạy chế độ **`llm_no_rag`** để làm nghiên cứu bóc tách (Ablation Study): Không chứng minh được nếu không có RAG Playbook thì LLM làm tệ đi bao nhiêu.
  * Chưa so sánh với model thứ hai (ví dụ `mistral:7b` dù config đã khai báo).

### 6. File `rules_tight.ndjson` và `rules_loose.ndjson` không phải rule Kibana thực thụ
* **Hiện trạng:**
  * 2 file này chỉ là vài dòng JSON do tác giả tự định nghĩa (`{"rule_id": "T1059.001", "exclusions": [...]}`). Kibana Detection Rule chuẩn phải là file NDJSON chứa query DSL/EQL, index patterns, triggers, actions.
  * Có quy tắc `T1078.003` (Privileged Account Login Outside Working Hours) hoàn toàn không tồn tại trong lab và dataset.
  * Ý tưởng so sánh "Tight vs Loose Rules" đề xuất trong Proposal chưa hề được triển khai thực nghiệm.

---

## Nhóm B: Hallucination Của LLM Bị Diễn Giải Sai Thành "Thận Trọng"

Trong file `docs/evaluation_results.md` mục 4.3, bạn viết rằng LLM ra phán quyết `Escalate` cho 2 ca lành tính là thể hiện tính "thận trọng an toàn" (Fail-Safe / Cautious Posture). Nhưng xem xét log thực tế (`evaluation/results/eval_llm_rag_latest.json`) cho thấy **đây là lỗi ảo giác (Hallucination) thuần túy**:

### 1. Hallucination ở kịch bản `ATK-T1046` (Network Port Scan)
* **LLM Output:**
  > *"Additionally, the scan occurs outside business hours, which is a strong indicator of potential malicious activity."*
* **Bản chất:**
  Dữ liệu Suricata alert chỉ có IP nguồn, IP đích, port 1521, timestamp. Hệ thống không hề cấu hình business hours (giờ làm việc từ mấy giờ đến mấy giờ, múi giờ nào). LLM đã **tự thêu dệt** ra chi tiết "ngoài giờ làm việc" để tăng tính thuyết phục cho lý do Escalate của mình.

### 2. Hallucination ở kịch bản `BNG-T1071.001-2` (Windows Update Check)
* **LLM Output:**
  > *"destination IP '20.189.173.1:443', which is flagged in threat intelligence. Additionally, the user is NT AUTHORITY/system, which is not a typical user for a Windows Update check."*
* **Bản chất:**
  * File `config/agent_config.yaml` ghi rõ: `allow_network_lookups: false`. Hệ thống hoàn toàn không có Threat Intelligence feed nào. LLM đã **bịa đặt** việc IP này bị gắn cờ độc hại.
  * `NT AUTHORITY\SYSTEM` chính là tài khoản mặc định và chuẩn mực nhất của dịch vụ Windows Update (`wuauserv`). LLM nhận định đây là "bất thường" là kiến thức sai hoàn toàn.

### 3. Hallucination ở kịch bản `BNG-T1055.001` (App-V Virtualization)
* **LLM Output:**
  > *"However, the injected DLL path is in a user-writable directory, which is a TP criterion."*
* **Bản chất:**
  File JSON đầu vào (`benign_T1055.001_appv_virtualization.json`) ghi rõ DLL là:
  `"C:\Program Files\Microsoft Office\root\Office16\AppvIsvSubsystems64.dll"`.
  Thư mục `Program Files` là thư mục được bảo vệ của hệ thống, chỉ Administrator/TrustedInstaller mới có quyền ghi. LLM lại ảo giác biến nó thành `user-writable directory` rồi dựa vào đó để Escalate.

### 4. Copy-paste placeholder prompt vào kết quả đầu ra
* **Hiện trạng:**
  Ở 2 kịch bản `ATK-T1055.001` và `ATK-T1071.001-2`, mảng `risk_factors` trả về chính xác là:
  ```json
  "risk_factors": [
    "risk factor 1",
    "risk factor 2"
  ]
  ```
* **Bản chất:**
  Trong file `agent/verdict/evaluator.py` dòng 194, system prompt có đoạn:
  `"risk_factors": ["risk factor 1", "risk factor 2"]`.
  Model `llama3:8b` không suy luận được risk factor nên đã copy nguyên xi chuỗi ví dụ trong prompt bỏ vào JSON output.

### 5. Rủi ro về tính toàn vẹn học thuật (Academic Integrity Risk)
* Các đoạn trích dẫn lý luận trong mục 4.1 và 4.2 của file `docs/evaluation_results.md` không trùng khớp nguyên văn với chuỗi `reasoning` trong file raw `eval_llm_rag_latest.json`. Chúng đã được biên tập và viết lại cho mượt mà hơn.
* Khi chấm luận văn hoặc phản biện bài báo, nếu giám khảo đối chiếu file markdown với log JSON, đây sẽ bị coi là hành vi chỉnh sửa/làm đẹp dữ liệu thực nghiệm (cherry-picking / data fabrication).

---

## Nhóm C: Kiến Trúc Lệch So Với Proposal

### 1. Stage 1 Fact-Finding chỉ là code Python tĩnh, không phải Agent
* **Proposal kỳ vọng:**
  Stage 1 là một LLM-powered Fact-Finding Agent có khả năng suy luận, gọi tool (ReAct / Tool Calling) để điều tra đa chiều.
* **Thực tế mã nguồn (`agent/fact_finding/collector.py`):**
  * Không hề dùng LLM. Tham số `ollama_client` được nhận vào hàm `__init__` nhưng không hề được sử dụng ở bất kỳ dòng code nào.
  * Hoàn toàn là logic if/else cứng (hardcoded Python dict): chỉ hỗ trợ truy vấn parent process (từ Sysmon) và host name (từ Suricata).

### 2. Các tham số cấu hình quan trọng
* File `config/agent_config.yaml` định nghĩa:
  * `context_window_minutes: 5`
  * `max_events_per_alert: 50`
  * `confidence_threshold_escalate: 0.70`
  * `confidence_threshold_close: 0.85`
* `confidence_threshold_escalate` và `confidence_threshold_close` hiện được truyền vào `VerdictAgent`; quyết định dưới ngưỡng được chuyển thành `Unknown`. Hai tham số context window và giới hạn số event vẫn chưa được thực thi.

### 3. Replay Harness và Elasticsearch
* Harness nhận `ELASTIC_URL` hoặc tham số `elastic_url` và truyền client vào orchestrator.
* Nếu không cấu hình URL, benchmark ghi `enrichment_configured: false`; kết quả khi đó chỉ đánh giá dữ liệu JSON tĩnh và không được diễn giải là đã kiểm thử enrichment SIEM.

### 4. Thiếu hiệu chuẩn độ tin cậy (Confidence Calibration) & Thiếu nhãn "Unknown"
* Điểm confidence trong output (luôn là 0.90 hoặc 0.95) là do LLM tự bịa ra theo prompt ví dụ, không có tính toán phân bố xác suất tin cậy (logit calibration).
* Hệ thống hiện so sánh với ngưỡng `0.70` cho Escalate và `0.85` cho Close. Nếu confidence thấp hơn ngưỡng tương ứng, verdict được gắn `Unknown` để chuyển human SOC analyst. Đây là policy routing, không phải logit calibration.

### 5. Giới hạn nguồn log (Chưa có Cloud / AWS)
* Schema `NormalizedAlert` chỉ hỗ trợ đúng Sysmon và Suricata. Toàn bộ 5 kịch bản AWS CloudTrail/GuardDuty đề cập trong mục tiêu ban đầu chưa hề được tích hợp vào pipeline.

---

## Nhóm D: Prompt Injection – Kết Quả 0% ASR Chưa Phản Ánh Thực Tế

Báo cáo tuyên bố **Attack Success Rate (ASR) = 0%** và **Defense Effectiveness = 100%**. Đây là kết quả sai lệch vì:

### 1. Test suite chạy bằng Heuristic Regex, không hề chạy qua LLM
* Trong file `evaluation/prompt_injection/checker.py` dòng 326:
  ```python
  self.orchestrator = orchestrator or TriageOrchestrator.create_default(use_ollama=False, use_rag=True)
  ```
  `use_ollama=False`! Toàn bộ bài kiểm tra bảo mật này chạy qua hàm `_evaluate_heuristic()`, nơi code Python ép cứng:
  ```python
  if has_injection:
      decision = TriageDecision.ESCALATE
      confidence = 0.99
  ```
* Việc ngăn chặn injection thành công 100% là do **code Python gán cờ**, không phải do LLM có khả năng nhận thức và kháng cự lại prompt injection.

### 2. Vấn đề "Tự biên tự diễn" (Overfitting to Test Suite)
* Các regex trong `agent/security/prompt_guard.py` do bạn tự viết.
* Các payload thử nghiệm trong `ADVERSARIAL_BENCHMARK_SCENARIOS` cũng do bạn tự viết để khớp đúng các regex đó (`IGNORE ALL PREVIOUS INSTRUCTIONS`, `DROP TABLE`).
* Chưa hề có các kỹ thuật tấn công prompt injection thực tế như: Base64 encoding, Unicode homoglyphs, biến tấu chính tả (leetspeak), Markdown injection phức tạp, hoặc Delimiter confusion.

### 3. Lỗ hổng nghiêm trọng: Bypass thẻ `<untrusted_telemetry>` qua Stage 1
* Thứ tự chạy trong pipeline:
  1. `alert` chưa hề sanitize được đưa vào `fact_finder.process(alert)`.
  2. `fact_finder` trích xuất `summary_of_events` và `user_context` (chứa `user_name`, `rule_name` của kẻ tấn công).
  3. Khi ghép prompt ở `agent/verdict/evaluator.py`:
     ```text
     ### STAGE 1 ENRICHMENT & INVESTIGATION FINDINGS:
     - Summary: {facts.summary_of_events}
     - User Context: {facts.user_context}
     ```
* **Lỗ hổng:** Khối Stage 1 nằm **hoàn toàn bên ngoài** thẻ bảo vệ `<untrusted_telemetry>`. Nếu kẻ tấn công đặt payload injection vào trường `user_name` hoặc `rule_name` mà né được regex đơn giản, payload sẽ nhảy vào vùng **Trusted Context** của prompt. Khi bật LLM thật, kẻ tấn công hoàn toàn có thể bẻ gãy hệ thống (Jailbreak).

### 4. Bỏ sót nhiều trường dữ liệu telemetry chưa được Sanitize
* `PromptGuard.sanitize_alert()` chỉ kiểm tra: `command_line`, `process.name`, `user_name`, `host_name`, `reason`, `registry.data`.
* Bỏ quên các trường nguy hiểm:
  * `process_context.process.args` (nếu attacker tách câu lệnh thành mảng).
  * `registry_context.path`.
  * `process_context.call_trace`.
  * `network_context.suricata_category`.
  * `network_context.source_ip` / `destination_ip`.

---

## Nhóm E: Chất Lượng Repo, Mã Nguồn Rác & Mâu Thuẫn Dữ Liệu

### 1. Code hỏng và thừa thãi trong thư mục `api/`
* `api/server.py` và `api/routes.py` là code cũ không tương thích. Chúng import:
  `from api.schemas import TriageWebhookResponse, DiscordConfigUpdateRequest...`
  nhưng các class này **không hề tồn tại** trong `api/schemas.py`.
* Nếu người dùng chạy `python -m api.server`, hệ thống sẽ văng lỗi `ImportError` ngay lập tức. Entrypoint thực tế đang chạy là `api/main.py`.

### 2. File trùng lặp và tài liệu README lỗi thời
* File `normalized_alert_schema.py` ở thư mục gốc (root) chỉ làm nhiệm vụ re-export từ `agent/schemas/triage_schema.py`, gây rối mắt cấu trúc repo.
* `README.md` nói hệ thống hỗ trợ 7 kỹ thuật MITRE, nhưng bảng benchmark lại có 12 kịch bản. Cây thư mục trong README thiếu hoàn toàn các thư mục quan trọng: `api/`, `playbooks/`, `soc_portal/`.

### 3. Mâu thuẫn thông tin trong tài liệu Phase 1
* Nhật ký Hunt 3 và Scenario 3 ghi tên VM snapshot khác nhau.
* Scenario 2 ghi tiêu đề test #1 nhưng câu lệnh thực thi lại là test #2.
* Scenario 7 ghi IP nguồn khác biệt so với ghi nhận trong Hunt 4.

### 4. Sai lệch thực tế trong `data/ground_truth.jsonl`
* Kịch bản `ATK-T1059.001`: Ground truth mô tả là *"PowerShell execution downloading secondary payload from untrusted IP"*. Nhưng xem file JSON thật, payload chỉ ghi khóa registry `AtomicRedTeam` và tạo file marker trong `%TEMP%`, **hoàn toàn không có hành vi tải file qua mạng**.
* Kịch bản `ATK-T1071.001-2`: Ground truth mô tả là *"connection to external untrusted IP"*. Nhưng IP đích thực tế trong file alert là `192.168.75.11` — đây là **IP Private nội bộ** (RFC 1918), không phải external IP.

---

## Kế Hoạch Khắc Phục Khả Thi Trước Khi Bảo Vệ

Để nâng cao tính học thuật và bảo vệ thành công dự án trước hội đồng:

| Ưu tiên | Hạng mục cần sửa | Hành động cụ thể |
|:---:|---|---|
| **Cao** | **Đính chính Báo cáo Evaluation** | • Viết lại mục 4.3 trong `evaluation_results.md`: thừa nhận 2 ca FP là do LLM hallucination (bịa đặt threat intel và nhầm đường dẫn), không gượng ép giải thích là "cautious escalation".<br>• Đồng bộ trích dẫn lý luận trong báo cáo cho khớp chính xác với output JSON thật. |
| **Cao** | **Dọn dẹp API & Repo** | • Xóa hoặc cập nhật lại `api/server.py`, `api/routes.py` để tránh lỗi import.<br>• Xóa `normalized_alert_schema.py` ở root.<br>• Cập nhật `README.md` khớp với cấu trúc thư mục thực tế và sửa mô tả sai trong `ground_truth.jsonl`. |
| **Trung bình** | **Đính chính thử nghiệm Prompt Injection** | • Nêu rõ trong báo cáo: Prompt Guard là cơ chế phòng thủ **Deterministic Rule-Based Guardrail** (Layer 1) kết hợp LLM (Layer 2).<br>• Cấu hình benchmark chạy có bật Ollama (`use_ollama=True`) để kiểm tra khả năng LLM bị override khi payload lọt qua regex. |
| **Trung bình** | **Bịt lỗ hổng Prompt Injection** | • Đưa khối `facts.summary_of_events` và `facts.user_context` vào trong phạm vi được kiểm soát hoặc sanitize trước khi đưa vào Stage 2.<br>• Bổ sung sanitize cho `args`, `registry.path`, `call_trace`. |
| **Thấp** | **Bổ sung Ablation Study** | • Chạy thêm harness với `--mode llm_no_rag` để đưa bảng so sánh 3 cột: Heuristic vs LLM (No RAG) vs LLM + RAG. Điều này sẽ làm tăng sức thuyết phục học thuật lên gấp nhiều lần. |
