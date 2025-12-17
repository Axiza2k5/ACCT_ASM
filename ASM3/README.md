# Proof of Concept (PoC): Tấn công Padding Oracle
Demo Video: [https://youtu.be/MuB8KgGaTLo]

## Tổng quan

*   `padding_oracle.py`: Script thực hiện tấn công Padding Oracle, cho phép giải mã từng block của bản mã (ciphertext) bí mật.
*   `chat_client.py`: Một client mô phỏng ứng dụng chat hợp lệ để giao tiếp với server.

## Cài đặt thư viện (Dependencies)

Bạn cần cài đặt các thư viện cần thiết sau:

*   `requests`
*   `cryptography`

```bash
pip install requests cryptography
```

## Chạy ứng dụng Chat (Task 2)

Khởi động client để bắt đầu phiên làm việc:

```bash
python3 chat_client.py
```

Lưu ý: Lệnh này sẽ khởi tạo một session, cho phép gửi và nhận tin nhắn mã hóa với Chat Bot.

## Thực thi tấn công Padding Oracle (Task 3)

Để bắt đầu giải mã, ta cần thực hiện theo các bước sau trong script `padding_oracle.py`:

1.  **Cập nhật Payload**: Copy một payload từ request gửi tin nhắn (trong session muốn tấn công). Payload này giúp script giả lập hành động gửi tin để lấy token mới, tránh việc sessionToken bị hết hạn (thường là sau 5 phút).
2.  **Nhập Ciphertext**: Paste đoạn mã cần giải mã vào biến `ciphertext_bytes_base64`.
3.  **Chạy script**:
    ```bash
    python3 padding_oracle.py
    ```

### Kết quả mẫu (Example Output)

Khi chạy, tool sẽ giải mã từng byte một, kết quả sẽ hiển thị tương tự như sau:

```
Attacking block 2...
Found byte 15: 0x61 ('a')
Found byte 14: 0x74 ('t')
...
Found byte 0: 0x73 ('s')

Attacking block 1...
...

Decrypted Result (Hex): ...
Decrypted Message: "Nội dung tin nhắn đã giải mã"
```

## Cơ chế giới hạn tốc độ (Rate Limiting)

Server hiện đang áp đặt giới hạn tốc độ xử lý khoảng 1 request/giây. Do đó, cả `padding_oracle.py` và `chat_client.py` đều đã được cấu hình để tuân thủ quy tắc này, tránh bị server chặn IP.

Việc này được xử lý bởi hàm `enforce_rate_limit()`:

### `enforce_rate_limit()` Function

```python
LAST_REQUEST_TIME = 0
RATE_LIMIT_LOCK = threading.Lock() # Đảm bảo thread-safe trong padding_oracle.py

def enforce_rate_limit():
    global LAST_REQUEST_TIME
    with RATE_LIMIT_LOCK:
        current_time = time.time()
        elapsed = current_time - LAST_REQUEST_TIME
        if elapsed < 1:
            # Ngủ (sleep) phần thời gian còn lại để đủ 1 giây
            time.sleep(1 - elapsed)
        LAST_REQUEST_TIME = time.time()
```

Giải thích: Trước mỗi lần gửi HTTP request, hàm này sẽ được gọi để kiểm tra thời gian trôi qua kể từ request cuối cùng. Nếu chưa đủ 1 giây, chương trình sẽ tự động "ngủ" trong khoảng thời gian còn thiếu. Điều này đảm bảo quá trình tấn công diễn ra liên tục mà không gây lỗi từ phía server.
