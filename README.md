# Shopee Review Monitor — Workflow n8n theo dõi & phân tích đánh giá Shopee

> **Trạng thái:** Workflow đã xây dựng, import vào n8n 2.42.5 và **test thực tế** (§7). Google Sheets **chưa chạy với credentials thật** (instance chưa có credential) — làm §4.2 rồi mới chạy thật.

| File | Mô tả |
|---|---|
| `shopee-monitor-workflow.json` | **Workflow chính để import** (50 nodes) |
| `shopee-monitor-mirror-test.json` | Bản test: node Google Sheets thay bằng Code giả lập → chạy end-to-end không cần Google |
| `build_workflow.py` | Script sinh ra 2 file trên (một nguồn code duy nhất) |
| `sample-data/*.csv` | Dữ liệu mẫu dán vào Google Sheets |
| `tests/` | Unit test HMAC + output các lần chạy test (bằng chứng) |

## 1. Nguồn dữ liệu Shopee — kiểm tra thực tế, không giả định

| Thử nghiệm | Kết quả thực tế | Kết luận |
|---|---|---|
| `GET shopee.vn/robots.txt` | Shop search/details bị Disallow; không có sitemap | Không có sitemap công khai |
| `GET` trang shop / sản phẩm / trang chủ | Cả3 URL trả về **cùng1 shell SPA 161.523 bytes**, không dữ liệu sản phẩm/bình luận | HTTP GET thuần không lấy được dữ liệu |
| `GET shopee.vn/api/v2/item/get_ratings?...` | **HTTP 403**, error `90309999` (chống bot) | Không tìm cách vượt CAPTCHA/chống bot (theo yêu cầu) |
| Shopee Open Platform | Tài liệu chính thức: `v2.product.get_item_list` (offset, page_size ≤100), `v2.product.get_comment` (cursor `comment_id`), host `partner.shopeemobile.com`, ký HMAC-SHA256 = `partner_id+path+timestamp+access_token+shop_id` bằng `partner_key` | **API chính thức, miễn phí**, cần đăng ký developer + cấp quyền shop bạn sở hữu |

**Hai chế độ (`DATA_SOURCE` trong node `Config`):**

- **`import` (mặc định — đã test end-to-end):** nguồn = dữ liệu bạn nhập vào sheet `ProductImports` / `ReviewImports` (dán tay từ trình duyệt hoặc CSV). Hoạt động hợp pháp với **mọi shop**.
- **`open_api`:** tự động đầy đủ (phân trang) qua Shopee Open Platform — **chỉ khi có credentials hợp lệ**. Mã đã cài, **chưa test API thật**; parser phòng thủ cho cả2 kiểu response.

Stage sản phẩm và đánh giá tách theo `IF - Product Source` / `IF - Review Source` → đổi nguồn không phải thiết kế lại.

## 2. Sơ đồ luồng

```
[Manual Trigger] + [Schedule Trigger (TẮT)] → [Config] → [Init Run Stats] → [Read Shops] → [Filter Enabled Shops]
  ╔══ [Loop Over Shops] (batchSize=1) ══╗   open_api? YES → [Sign]→[HTTP get_item_list]→[Map API Products]
  ║  (lỗi → [Shop Error]: ghi lỗi + quay loop, KHÔNG kill run)   NO → [Read Product Imports]
  ║→ [Normalize Products] (dedupe+caps, LUÔN ≥1 item: products hoặc marker)
  ╚══ quay loop ── DONE → [Collect Discovered Products] → [IF Any Products?]
         NO → [Build Shop Status Rows] (finalize)     YES → [Upsert Products]
  ╔══ [Loop Over Products] ══╗
  ║ [Throttle] → [Read Product Reviews] (review đã có: dedupe + pending) → [Build Product State]
  ║   open_api? YES → [Init]⇄[Sign]⇄[HTTP get_comment]⇄[Parse]⇄[IF More Pages?]   NO → [Read Review Imports]
  ║ → [Normalize Reviews] → [Deduplicate Reviews] → [IF New Reviews?] YES → [Save Reviews]
  ║ → [Build Analysis Queue] (queue = pending cũ + mới, max AI/product)   NO ─┘
  ╚══ quay loop ── DONE → [IF Analysis Needed?]
        NO ──────────────────────────────┐
        YES → ╔══ [Loop Over Analysis Items] ══╗
              ║ [Throttle AI]→[Build Payload]→[HTTP Ollama Chat]→ ok: [Parse Analysis] / err: [Mark Failed]
              ║ → [Update Analysis] (match review_key) ; err Sheets → [Log Analysis Error] → quay loop
              ╚══ DONE ────────────────────────────┘
  → [Build Product Checks] → [Update Product Check] (batch1 lần)
  → [Build Shop Status Rows] → [Update Shop Status] (batch1 lần) → [Build Run Log] → [Save Run Log] = HẾT
```

3 vòng lặp chạy **tuần tự, không lồng nhau** — test (`tests/test_nested_loop.json`) chứng minh SplitInBatches lồng nhau bị lỗi context (vòng trong không chạy lại cho shop thứ2). Mọi nhánh IF nối lại về1 node điều khiển; mỗi node guarantee ≥1 item → luồng không bị đứt.

---

**3 vòng lặp chạy TUẦN TỰ, không lồng nhau** (Shop → Product → Analysis). Bắt buộc vì test thực tế (`tests/test_nested_loop.json`) chứng minh **SplitInBatches lồng nhau bị lỗi context**: vòng trong không chạy lại cho shop thứ2. Mọi nhánh IF được nối lại về1 node điều khiển để luồng không bị đứt (mỗi node guarantee ≥1 item hoặc có đường vòng).

---

## 3. Cấu trúc Google Sheets `Shopee Monitor` (6 sheet)

| Sheet | Cột | Vai trò |
|---|---|---|
| `ShopList` | `shop_name, shop_url, shop_id, enabled, last_checked_at, status, error_message` | **Bạn nhập** các dòng đầu;3 cột sau workflow tự ghi. Thêm/bớt shop không cần sửa workflow. `shop_id` để trống cũng được (workflow tự trích từ URL). |
| `Products` | `shop_id, shop_name, item_id, product_name, product_url, last_review_check, status` | Workflow tự tạo/cập nhật (upsert theo `shop_id+item_id`) |
| `Reviews` | `review_key, shop_id, shop_name, item_id, product_name, comment_id, rating_star, comment, review_time, collected_at, sentiment, issues, summary, urgency, analysis_status` | Khóa chống trùng = `shop_id_item_id_comment_id`. `analysis_status`: `pending`/`done`/`failed` (đặt lại `pending` để phân tích lại) |
| `ProductImports` | `shop_id, item_id, product_name` | **Bạn nhập** (chế độ `import`) — sản phẩm cần theo dõi |
| `ReviewImports` | `shop_id, item_id, comment_id, rating_star, comment, review_time` | **Bạn nhập** (chế độ `import`) — đánh giá mới (dán từ trình duyệt/CSV). Hỗ trợ `review_time` dạng epoch giây/ms hoặc ISO |
| `RunLog` | `run_started_at, run_finished_at, shops_total, shops_ok, shops_failed, products_discovered, reviews_new, analyses_done, analyses_failed, errors` | Lịch sử mỗi lần chạy (workflow tự ghi) |

Dán dữ liệu mẫu từ `sample-data/*.csv` vào3 sheet nhập liệu (giữ nguyên hàng tiêu đề ở dòng1).

---

## 4. Hướng dẫn cài đặt từng bước

### 4.1 Import workflow
1. n8n → **Workflows → Import from File** → chọn `shopee-monitor-workflow.json`.
2. Hoặc CLI (nếu chạy bằng Docker):
   ```bash
   docker cp shopee-monitor-workflow.json <container>:/tmp/main.json
   docker exec <container> n8n import:workflow --input=/tmp/main.json
   ```

### 4.2 Credential Google Sheets (bắt buộc, do bạn tạo)
Instance hiện tại **chưa có credential nào**. Chọn1 trong2 cách (n8n → Credentials → New → **Google Sheets**):

- **Service Account (khuyến nghị cho server):** Google Cloud Console → tạo project → bật *Google Sheets API* + *Google Drive API* → *Service Accounts* → tạo key JSON → import vào n8n → **share spreadsheet** cho email client email (Editor).
- **OAuth2:** cùng2 API trên → *OAuth Client ID (Desktop app)* → copy Client ID/Secret vào n8n → hoàn tất consent.

Gán credential này cho **cả9 node `Google Sheets - *`**.

### 4.3 Điền Spreadsheet ID
Lấy ID từ URL spreadsheet (`https://docs.google.com/spreadsheets/d/<ID>/edit`), thay giá trị `__FILL_SPREADSHEET_ID__` ở **Resource Locator `Document ID`** của9 node Google Sheets (mỗi node mở ra → tab Document ID → chế độ ID → dán). **Đây là node duy nhất bắt buộc điền tay ngoài credential.**

### 4.4 Ollama — kết nối từ container n8n (quan trọng)
`localhost` trong container KHÔNG phải máy host. Ollama mặc định chỉ nghe `127.0.0.1:11434`. Đã test: container n8n truy cập được Ollama qua **địa chỉ gateway Docker** `http://172.24.0.1:11434/api/chat` sau khi mở1 forward. Chọn1 trong2:

**Phương án A — socat (không cần sudo, chỉ nghe trên bridge network), đã dùng khi test:**
```bash
sudo apt install socat
nohup socat TCP-LISTEN:11434,bind=172.24.0.1,fork,reuseaddr TCP:127.0.0.1:11434 >/tmp/ollama_proxy.log 2>&1 &
# cho chạy lại khi reboot (systemd --user):
mkdir -p ~/.config/systemd/user
#   tạo unit ollama-proxy.service với ExecStart=socat TCP-LISTEN:11434,bind=172.24.0.1,fork,reuseaddr TCP:127.0.0.1:11434
systemctl --user enable --now ollama-proxy
```

**Phương án B — cho Ollama nghe tất cả interface (cần sudo, mở rộng ra LAN — dùng firewall để giới hạn):**
```bash
sudo mkdir -p /etc/systemd/system/ollama.service.d
sudo tee /etc/systemd/system/ollama.service.d/override.conf <<'EOF'
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
EOF
sudo systemctl daemon-reload && sudo systemctl restart ollama
```

Kiểm tra từ trong container:
```bash
docker exec <container> wget -qO- http://172.24.0.1:11434/api/version   # phải ra {"version":"..."}
docker exec <container> wget -qO- http://172.24.0.1:11434/api/tags      # xem model
```
Model dùng sẵn: `qwen2.5-coder:1.5b` (đổi bằng `ollama pull <model>` rồi sửa `OLLAMA_MODEL`).

### 4.5 Node `Config` — các biến
Mở node **Config** (Set) và sửa nếu cần:

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `DATA_SOURCE` | `import` | `import` hoặc `open_api` |
| `OLLAMA_ENABLED` | `true` | `false` = bỏ qua phân tích (review giữ `pending`) |
| `OLLAMA_URL` | `http://172.24.0.1:11434/api/chat` | Địa chỉ Ollama từ trong container |
| `OLLAMA_MODEL` | `qwen2.5-coder:1.5b` | Model bất kỳ đã cài |
| `MAX_SHOPS` / `MAX_PRODUCTS_PER_SHOP` / `MAX_REVIEWS_PER_PRODUCT` / `MAX_AI_PER_PRODUCT` | 10/20/50/10 | Giới hạn mỗi lần chạy |
| `MAX_REVIEW_PAGES` / `REVIEW_PAGE_SIZE` | 3/20 | Phân trang (chế độ `open_api`) |
| `REQUEST_DELAY_MS` / `AI_DELAY_MS` | 1000/500 | Chậm giữa các request / lượt AI |
| `SHOPEE_API_HOST` / `SHOPEE_PARTNER_ID` / `SHOPEE_ACCESS_TOKEN` / `SHOPEE_PARTNER_KEY` | host mặc định + rỗng | Chỉ cần khi `DATA_SOURCE=open_api` (lấy từ developer.shopee.com sau khi đăng ký app và cấp quyền shop) |

### 4.6 Chạy thử & bật lịch
1. Chạy **Manual Trigger**1 lần → xem tab **Executions** → mở node từng bước để kiểm tra output (§6).
2. Kiểm tra6 sheet đã ghi đúng.
3. **Chỉ sau khi OK:** bật node `Schedule Trigger` (mặc định6h/lần, sửa trong node) và Active workflow.

---

## 5. Danh sách50 nodes theo nhóm

| Nhóm | Nodes (type) | Nhiệm vụ |
|---|---|---|
| Trigger & cấu hình | `Manual Trigger` (manualTrigger) · `Schedule Trigger` (scheduleTrigger, **disabled**) · `Config` (set3.5 —16 biến) · `Init Run Stats` (code) | Khởi động, lịch chạy (tắt đến khi test xong), cấu hình, reset bộ đếm |
| Vòng lặp | `Loop Over Shops` · `Loop Over Products` · `Loop Over Analysis Items` (splitInBatches3, batchSize=1) |3 vòng tuần tự; output0=done / output1=loop |
| Khám phá sản phẩm | `IF - Product Source` (if2.3) · `Code - Build Product Sign` (HMAC-SHA256 thuần JS — sandbox n8n chặn `require('crypto')`) · `HTTP - Shopee Get Item List` (httpRequest4.5, retry3×5s) · `Code - Map API Products` · `Read Product Imports` (Sheets read, alwaysOutputData) · `Code - Normalize Products` | Chọn nguồn, ký API, chuẩn hoá, luôn≥1 item |
| Ghi sản phẩm | `Code - Collect Discovered Products` · `IF - Any Products` · `Upsert Products` (Sheets **appendOrUpdate**, match `[shop_id,item_id]`) | Gộp mọi shop, dedupe, upsert |
| Thu thập đánh giá | `Code - Throttle` · `Read Product Reviews` (Sheets) · `Code - Build Product State` · `IF - Review Source` · `Read Review Imports` (Sheets) · `Code - Init/Build Sign/Parse Comments Page` · `HTTP - Shopee Get Comments` · `IF - More Review Pages` (vòng cursor `comment_id`, dừng khi gặp review đã biết) · `Code - Collect/Normalize Reviews` · `Code - Deduplicate Reviews` (khóa `shop_id_item_id_comment_id`) · `IF - New Reviews` · `Save Reviews` (append, status=pending) | Phân trang + incremental, chuẩn hoá, chống trùng |
| Phân tích AI | `Code - Build Analysis Queue` (pending cũ+mới, cap AI/product) · `IF - Analysis Needed` · `Code - Throttle AI` · `Code - Build Ollama Payload` (prompt tiếng Việt nghiêm ngặt, `format:"json"`, `temperature:0.1`) · `HTTP - Ollama Chat` (retry3×5s) · `Code - Parse Analysis` (validate enum) · `Code - Mark Analysis Failed` (failed=trạng thái đỉnh — retry có giới hạn) · `Update Analysis` (Sheets update match `review_key`) · `Code - Log Analysis Error` | Gọi Ollama local; review `done` KHÔNG gửi lại |
| Tổng kết & lỗi | `Code - Build Product Checks` · `Update Product Check` (batch) · `Code - Build Shop Status Rows` · `Update Shop Status` (batch) · `Build/Save Run Log` · `Code - Shop Error` · `Code - Product Error` | Cập nhật batch cuối run, ghi lịch sử, cô lập lỗi |

**Chống đứt luồng:** `retryOnFail(2–3 lần)` + `onError: continueErrorOutput` → error output về router lỗi → quay loop. Mọi Code node sinh dữ liệu set `pairedItem` thủ công để `$('...').item` hoạt động xuyên node (đã test). Anti-pattern đã phát hiện & tránh: **nested SplitInBatches** (T4) và **node0 item bị skip làm treo loop** (giải pháp: `alwaysOutputData` + marker ≥1 item).

## 6. Kiểm tra output sau từng bước (checklist nhanh)

Chạy Manual Trigger → **Executions → mở từng node**, so sánh:

1. `Config` —16 biến, `DATA_SOURCE=import`.
2. `Read Shops` — các dòng shop từ sheet.
3. `Filter Enabled Shops` — chỉ shop enabled (TRUE/1/yes); `shop_id` đã trích từ URL.
4. `Normalize Products` —1 dòng/sản phẩm + `product_url`; shop không có hàng import →1 dòng `_marker=no_products`.
5. `Upsert Products` —7 cột đúng.
6. `Build Product State` — `existing_keys` (review đã có) + `pending` (cần phân tích lại).
7. `Deduplicate Reviews` — dòng mới có `review_key`; không có mới → `_marker=no_new_reviews`.
8. `Save Reviews` —15 cột, `analysis_status=pending`.
9. `HTTP - Ollama Chat` → `Parse Analysis` — JSON hợp lệ, đúng enum (`positive/neutral/negative`, `low/medium/high`, issues∈6 giá trị).
10. Cuối run: sheet `Reviews` đã có sentiment/issues/summary/urgency; `RunLog`1 dòng đủ10 cột; `ShopList` cập nhật `status`.

**Test không cần Google:** import `shopee-monitor-mirror-test.json` → chạy → mọi node Sheets chạy bằng Code giả lập (mẫu:2 shop bật/1 tắt,3 sản phẩm,7 review import,2 review seed).

---

## 7. Kết quả test đã thực hiện (lưu trong `tests/`)

| Test | File | Kết quả |
|---|---|---|
| HMAC-SHA256 thuần JS vs crypto thật (RFC4231, UTF-8, key>64B) | `tests/sha256_hmac_test.js` | **8/8 PASS** |
| Context ref `$('...').item` trong loop xuyên node | `tests/test_ctx_ollama.json` | PASS — đúng theo từng iteration |
| Error output giữ context (shop_id/item_id) | `tests/test_error_output.json` | PASS — `{...input, error}` + pairedItem |
| **Nested SplitInBatches** | `tests/test_nested_loop.json` | **FAIL có chủ đích** → thiết kế3 vòng tuần tự |
| Ollama qua HTTP node trong n8n (JSON hợp lệ tiếng Việt) | `tests/test_code_crypto.json` | PASS |
| **Mirror end-to-end** (2 shop bật/1 tắt, dedupe, Ollama5 lượt) | `tests/mirror_run_output.json` | **PASS** — RunLog: `2 ok/0 failed, 3 products, 4 reviews_new, 5 analyses_done, 0 errors`; review `done` KHÔNG bị phân tích lại;5/5 kết quả enum hợp lệ, summary tiếng Việt |
| E1 — fetch shop lỗi (host chết) | `tests/e1_output.json` | Workflow **vẫn success**;2 shop `status=error`, message rõ (`connect ECONNREFUSED...`), retry3×5s hoạt động |
| E2 — Ollama chết | `tests/e2_output.json` | Workflow **vẫn success**;4 review lưu bình thường,5 review → `analysis_status=failed` (retry có giới hạn) |
| Workflow chính chạy thật (chưa có credentials) | `tests/main_run_output.json` | Dừng đúng tại `Read Shops`: `"Node does not have any credentials set"` (hành vi mong đợi; mọi node trước đó hợp lệ) |

**Nghiệm thu:** ✅ thêm nhiều shop không sửa workflow · ✅ quan hệ shop→sản phẩm→đánh giá · ✅ chống trùng theo khóa ổn định, không phân tích lại `done` · ✅ Ollama tiếng Việt · ✅ kết quả ghi Sheets · ✅ lỗi1 shop không kill run · ✅ bật/tắt shop bằng `enabled` · ✅ lịch sử chạy ở `RunLog` · ✅ nguồn dữ liệu xác minh thật. ⏳ **Còn lại (cần bạn):** Google credentials + Spreadsheet ID (§4.2–4.3); `open_api` cần partner credentials Shopee.

## 8. Hạn chế đã biết

1. **`open_api` chưa test với API thật** (chưa có credentials); parser hỗ trợ2 kiểu response — kiểm lại1 lần khi có credentials.
2. Quota Google API: mỗi1 sản phẩm =1–2 lần đọc Sheets; tăng `MAX_PRODUCTS_PER_SHOP` quá cao → chạm quota (~60 đọc/phút/dự án) → tăng `REQUEST_DELAY_MS`.
3. Bộ đếm run (static data) chỉ sống trong1 lần chạy — mỗi run tự reset (có chủ đích).
4. `analysis_status=failed` là trạng thái đỉnh: muốn phân tích lại thì đặt ô đó về `pending`.
5. Review `pending` bị lỗi Ollama sẽ được thử lại ở run sau (khi sản phẩm được quét tới).
6. Model nhỏ (`qwen2.5-coder:1.5b`) thỉnh thoảng gán `issues` rộng hơn thực tế — đổi `OLLAMA_MODEL` sang model lớn hơn nếu cần chính xác hơn.

