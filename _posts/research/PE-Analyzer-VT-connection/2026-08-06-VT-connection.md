---
title: "PE Analyzer Project - VirusTotal API Connection"
date: 2026-08-06
categories: [research]
tags: [reverse]
description: ""
---

## What is VirusTotal ?
VirusTotal (VT) là một dịch vụ trực tuyến tổng hợp thông tin tình báo mối đe dọa (Threat Intelligence) thuộc sở hữu của Google (Chronicle Security). Nền tảng này cho phép người dùng và các hệ thống bảo mật tự động gửi tệp tin, mã băm (MD5/SHA-1/SHA-256), tên miền (Domain), địa chỉ IP hoặc URL để phân tích mức độ độc hại.

Công dụng chính của VirusTotal trong Malware Analyst và SOC Analyst:
```
                        ┌────────────────────────────────────────┐
                        │      FILE HASH (MD5 / SHA-256)         │
                        └───────────────────┬────────────────────┘
                                            │
                                  [ VirusTotal API v3 ]
                                            │
          ┌─────────────────┬───────────────┴───────────────┬─────────────────┐
          ▼                 ▼                               ▼                 ▼
   [ 70+ AV Engines ] [ Threat Attribution ]     [ Dynamic Sandbox ]  [ Community & Graph ]
  - Kaspersky: Wanna  - Họ mã độc: Ransomware    - Registry modify    - Domain/IP liên kết
  - BitDefender: Gen  - Nguồn gốc APT Group      - Network Beaconing  - YARA rule matches
  - Microsoft: Trojan - Tỉ lệ phát hiện: 63/71   - File dropped       - Threat Actor tags
```

- Tập hợp đa bộ máy quét: VT tích hợp đồng thời hơn 70+ giải pháp diệt virus và bộ máy phân tích hàng đầu. Qua đó cung cấp góc nhìn đa chiều với chỉ số thống kê `positives / total_engines` giúp đánh giá mức độ nguy hiểm với độ tin cậy cao
- Giảm thiểu báo động giả (False Positive) và Bỏ sót (False Negative): 
    
    - False Positive: Trên VT, chỉ cần 1 vài hãng phát hiện dấu hiệu bất thường, hệ thống đã ghi nhận cảnh báo.
    - False Negative: Nếu chỉ 1 engine lạ gắn cờ trong khi 70 engine uy tín khác báo "Clean", chuyên viên có thể nhận định đây là phần mềm an toàn bị nhận diện nhầm.

- Định danh - phân loại Malware (Malware Family Attribution): VT hỗ trợ trích xuất tên định dang cụ thể từ các engine uy tín (Kaspersky, Bitdefender,...)
- Tiết kiệm tài nguyên và thời gian phân tích sự cố: Thay vì phải thiết lập môi trường Sandbox nặng nề và mất 5–10 phút để chạy phân tích động (Dynamic Analysis), chỉ cần tính toán mã băm SHA-256 (mất < 1 giây) và gửi lên VirusTotal API để nhận ngay toàn bộ lịch sử phân tích đã tồn tại trong cơ sở dữ liệu toàn cầu.

## Interacting with VirusTotal REST API v3

### Main target
Module này được tạo nhằm mục đích thực hiện giao tiếp với **VT RESR API v3** thông qua giao thức `HTTPS` để tra cứu thông tin của file hash (`MD5/sha256`), đồng thời bóc tách kết quả phân tích thống kê và chi tiết từ các Antivirus Engine mục tiêu

### Xây dựng module

#### Xác định cơ chế

Endpoint chuẩn: 
```
GET https://www.virustotal.com/api/v3/files/{file_hash}
```

Cơ chế xác thực: Truyền API Key qua HTTP Header
```
x-apikey: {VT_API_KEY}
```

#### Xây dựng CTDL và hệ thống Ngoại lệ

Xây dựng Cây phân cấp ngoại lệ dựa trên HTTP Status Code. Cụ thể:
- `HTTP 401` và `HTTP 403`: Lỗi xác thực (Unauthorized và Forbidden)
- `HTTP 404`: Not found, tức hash chưa từng xuất hiện trên VirusTotal
- `HTTP 429`: Vượt giới hạn Request của API key

```python
Exception
   └── VTErrors (Ngoại lệ cơ sở cho toàn bộ lỗi liên quan đến VirusTotal API)
         ├── VTAuthErrors       (Lỗi xác thực: 401 Unauthorized, 403 Forbidden, thiếu API Key)
         ├── VTNotFoundErrors   (Lỗi 404: Hash chưa từng xuất hiện trên VirusTotal)
         ├── VTRateLimitErrors  (Lỗi 429: Vượt ngưỡng hạn mức Request giới hạn của API Key)
         └── VTRequestErrors    (Lỗi mạng, timeout, hoặc cấu trúc JSON trả về bị sai)
```

Xây dựng CTDL cho kết quả trả về từ VT:
```python
@dataclass
class VTResult:
    file_hash: str                               # Hash được tra cứu (MD5 hoặc SHA-256)
    malicious: int                               # Số lượng engine cảnh báo độc hại
    total_engines: int                           # Tổng số engine tham gia quét
    is_flagged: bool                             # True nếu malicious > 0
    file_type: str                               # Định dạng file (type_description)
    permalink: str                               # Đường dẫn xem báo cáo GUI trực quan
    engine_detections: Dict[str, Optional[str]] = field(default_factory=dict)
    # Kết quả phân tích chi tiết của các AV mục tiêu (Kaspersky, Bitdefender, Microsoft, v.v.)
```

#### Xây dựng hàm thành viên

Xây dựng `get_API_key()` để get `VT_API_KEY` từ biến môi trường hệ thống `os.getenv`.

Xây dựng `validate_hash(file_hash)` kiểm tra tính hợp lệ của mã băm trước khi gửi HTTP Request (tránh lãng phí hạn mức API cho các chuỗi rác). Cụ thể, thực hiện kiểm tra qua các bước sau:
- Step 1: Loại bỏ khoảng trắng thừa và đồng bộ về chữ thường 
    ```python
    file_hash.strip().lower()
    ```
- Step 2: Regex Validation
    ```
    MD5: ^[a-f0-9]{32}$
    sha256: ^[a-f0-9]{64}$
    ```
- Step 3: Exception. Trả về `ValueError` nếu không khớp

Xây dựng `parse_VT_response(data, file_hash)` để bóc tách dữ liệu phản hồi JSON từ VT API v3. Quá trình bóc tách được thực hiện như sau:

- **Step 1**: Kiểm tra cấu trúc gốc bằng `isinstance()`:
    ```python
    if not isinstance(data, dict) or 'data' not in data or 'attributes' not in data['data']:
        raise VTRequestErrors()
    ```
- **Step 2**: Tính toán
    ```python
    malicious = stats.get("malicious", 0)
    total_engines = sum(stats.values())
    ```
- **Step 3**: Duyệt qua danh sách `target_engines`. Nếu engine có trong kết quả, lấy giá trị chuỗi `engine_data.get("result")`, ngược lại gán `None`
    ```python
    for engine in target_engines:
        engine_data = analysis_results.get(engine)
        if engine_data and isinstance(engine_data, dict):
            # Result has a 'result' field, which can be None or a string indicating the detection
            engine_detections[engine] = engine_data.get("result")
        else:
            engine_detections[engine] = None
    ```
- **Step 4**: Return về một `VTResult`

![alt text](https://github.com/UITxWoodyNguyen/myblog/blob/main/_posts/research/PE-Analyzer-VT-connection/image.png?raw=true)

Xây dựng `check_hash(file_hash, api_key, session)` nhằm thực hiện điều phối quá trình Send Request và xử lý HTTP Status Code. Quy trình cụ thể:

![alt text](https://github.com/UITxWoodyNguyen/myblog/blob/main/_posts/research/PE-Analyzer-VT-connection/image-1.png?raw=true)

### Kiểm tra Module

**Check code**:
```python
'''
This file is used to check for "/src/services/vt_checker.py" file.
Usage: pytest test_vt_checker.py -v
'''

from unittest.mock import MagicMock, patch
from pathlib import Path
import sys
import pytest

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

import src
from src.services.vt_checker import (
    check_hash,
    get_API_key,
    VTAuthErrors,
    VTNotFoundErrors,
    VTRateLimitErrors,
    VTRequestErrors,
)

VALID_SHA256 = "dc1869706aefb787daeeddea3865f7208fda26d470474db41ea10f40624beb80"
VALID_MD5 = "208a1aa0d4c07aa664cbae0e7b0b296e"

def _mock_response (status_code: int, json_data: dict | None = None, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = text

    return resp

def _mock_session (response: MagicMock) -> MagicMock:
    session = MagicMock()
    session.get.return_value = response

    return session

# Validate hashing type before calling the VT API
@pytest.mark.parametrize("bad_hash", ["", "abc", "z" * 64, "12345"])
def test_invalid_hash_format (bad_hash: str):
    with pytest.raises(ValueError):
        check_hash(bad_hash, api_key = "fake_key")

@pytest.mark.parametrize("good_hash", [VALID_MD5, VALID_SHA256])
def test_valid_hash_format (good_hash):
    payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 70, "suspicious": 0, "undetected": 0, "timeout": 0}}}}
    session = _mock_session(_mock_response(200, json_data = payload))
    result = check_hash(good_hash, api_key = "fake_key", session = session)
    assert result.file_hash == good_hash

# API Key Handling
def test_API_key_raises_when_missing (monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising = False)
    with pytest.raises(VTAuthErrors):
        get_API_key()

def test_API_key_read_from_env (monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "env_key")
    assert get_API_key() == "env_key"

def test_check_hash_uses_env_key_when_not_passed (monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "env_key_value")
    payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 1, "suspicious": 0, "undetected": 0, "timeout": 0}}}}
    session = _mock_session(_mock_response(200, json_data = payload))

    check_hash(VALID_SHA256, session = session)

    called_headers = session.get.call_args[1]["headers"]
    assert called_headers["x-apikey"] == "env_key_value"

# Parse HTTP 200 response
def test_parses_clean_file_correctly():
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0, "suspicious": 0, "harmless": 68,
                    "undetected": 2, "timeout": 0,
                },
                "reputation": 10,
                "type_description": "Win32 EXE",
            }
        }
    }
    session = _mock_session(_mock_response(200, payload))
    result = check_hash(VALID_SHA256, api_key="fake_key", session=session)

    assert result.malicious == 0
    assert result.is_flagged is False
    assert result.total_engines == 70
    assert result.file_type == "Win32 EXE"
    assert VALID_SHA256 in result.permalink


def test_parses_malicious_file_correctly():
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 45, "suspicious": 3, "harmless": 20,
                    "undetected": 2, "timeout": 0,
                },
            }
        }
    }
    session = _mock_session(_mock_response(200, payload))
    result = check_hash(VALID_SHA256, api_key="fake_key", session=session)

    assert result.malicious == 45
    assert result.is_flagged is True


def test_missing_stats_defaults_to_zero():
    payload = {"data": {"attributes": {}}}
    session = _mock_session(_mock_response(200, payload))
    result = check_hash(VALID_SHA256, api_key="fake_key", session=session)

    assert result.malicious == 0
    assert result.total_engines == 0
    assert result.is_flagged is False

# HTTP Error Handling
def test_401_raises_vtautherror():
    session = _mock_session(_mock_response(401, text="Wrong API key"))
    with pytest.raises(VTAuthErrors):
        check_hash(VALID_SHA256, api_key="bad_key", session=session)


def test_403_raises_vtautherror():
    session = _mock_session(_mock_response(403, text="Forbidden"))
    with pytest.raises(VTAuthErrors):
        check_hash(VALID_SHA256, api_key="bad_key", session=session)


def test_404_raises_vtnotfounderror():
    session = _mock_session(_mock_response(404, text="Not found"))
    with pytest.raises(VTNotFoundErrors):
        check_hash(VALID_SHA256, api_key="fake_key", session=session)


def test_429_raises_vtratelimiterror():
    session = _mock_session(_mock_response(429, text="Too many requests"))
    with pytest.raises(VTRateLimitErrors):
        check_hash(VALID_SHA256, api_key="fake_key", session=session)


def test_unexpected_status_raises_vtrequesterror():
    session = _mock_session(_mock_response(500, text="Internal Server Error"))
    with pytest.raises(VTRequestErrors):
        check_hash(VALID_SHA256, api_key="fake_key", session=session)


def test_malformed_json_raises_vtrequesterror():
    session = _mock_session(_mock_response(200, json_data=None))
    with pytest.raises(VTRequestErrors):
        check_hash(VALID_SHA256, api_key="fake_key", session=session)


def test_missing_expected_keys_raises_vtrequesterror():
    session = _mock_session(_mock_response(200, json_data={"unexpected": "shape"}))
    with pytest.raises(VTRequestErrors):
        check_hash(VALID_SHA256, api_key="fake_key", session=session)

# Network Error Handling / Timeouts
def test_timeout_raises_vtrequesterror():
    import requests as requests_module

    session = MagicMock()
    session.get.side_effect = requests_module.exceptions.Timeout()
    with pytest.raises(VTRequestErrors):
        check_hash(VALID_SHA256, api_key="fake_key", session=session)


def test_connection_error_raises_vtrequesterror():
    import requests as requests_module

    session = MagicMock()
    session.get.side_effect = requests_module.exceptions.ConnectionError()
    with pytest.raises(VTRequestErrors):
        check_hash(VALID_SHA256, api_key="fake_key", session=session)

# Format Headers and Endpoint
def test_api_key_sent_via_header_not_url():
    payload = {"data": {"attributes": {"last_analysis_stats": {"harmless": 1}}}}
    session = _mock_session(_mock_response(200, payload))

    check_hash(VALID_SHA256, api_key="super_secret_key", session=session)

    call = session.get.call_args
    url_arg = call.args[0] if call.args else call.kwargs.get("url", "")
    assert "super_secret_key" not in url_arg
    assert call.kwargs["headers"]["x-apikey"] == "super_secret_key"


def test_correct_endpoint_called():
    payload = {"data": {"attributes": {"last_analysis_stats": {"harmless": 1}}}}
    session = _mock_session(_mock_response(200, payload))

    check_hash(VALID_SHA256, api_key="fake_key", session=session)

    call = session.get.call_args
    url_arg = call.args[0] if call.args else call.kwargs.get("url", "")
    assert url_arg == f"https://www.virustotal.com/api/v3/files/{VALID_SHA256}"
```

![alt text](https://github.com/UITxWoodyNguyen/myblog/blob/main/_posts/research/PE-Analyzer-VT-connection/image-2.png?raw=true)