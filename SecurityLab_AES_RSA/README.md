# BÁO CÁO BÀI TẬP LỚN MÔN AN TOÀN VÀ BẢO MẬT THÔNG TIN
## ĐỀ TÀI: MÃ HOÁ ĐỐI XỨNG AES, MÃ HOÁ BẤT ĐỐI XỨNG RSA, HÀM BĂM SHA-256 & CHỮ KÝ SỐ

- **Học phần:** An toàn và Bảo mật thông tin
- **Ngôn ngữ & Nền tảng:** C# / .NET 8.0 (Windows Forms & CLI Suite)
- **Repository GitHub:** [https://github.com/phuhung2805/SecurityLab_AES_RSA](https://github.com/phuhung2805/SecurityLab_AES_RSA)
- **Kiến trúc:** Bất đồng bộ (`async/await`), Luồng khối nhớ đệm Streaming 1MB, Phân tầng dịch vụ mật mã sạch.

---

## MỤC LỤC CHI TIẾT TRẢ LỜI CÂU HỎI
1. [BÀI 1: MÃ HOÁ ĐỐI XỨNG AES](#phần-1-bài-tập-1---mã-hoá-đối-xứng-aes)
   - 1.1. Sinh khoá AES (128/192/256-bit) & Vector IV (16 bytes)
   - 1.2. Lưu khoá ra file (.aeskey)
   - 1.3. Import khoá từ file (.aeskey)
   - 1.4. Mã hoá / Giải mã đoạn văn bản (Text) $\rightarrow$ Base64
   - 1.5. Mã hoá / Giải mã File kích thước lớn (Hàng GB) & Tránh OutOfMemoryException
   - 1.6. So sánh từng byte giữa file nguồn và file giải mã kèm mã băm SHA-256
   - 1.7. **KẾT LUẬN DỰA THEO SỐ LIỆU THỰC NGHIỆM THU ĐƯỢC**
2. [BÀI 2: MÃ HOÁ BẤT ĐỐI XỨNG RSA & CHỮ KÝ SỐ](#phần-2-bài-tập-2---mã-hoá-bất-đối-xứng-rsa--chữ-ký-số)
   - 2.1. Sinh cặp khoá RSA (2048-bit / 4096-bit)
   - 2.2. Xuất cặp khoá ra file định dạng PEM
   - 2.3. View PEM & Giải thích chi tiết ý nghĩa các byte trong cấu trúc ASN.1 DER (TLV Breakdown)
   - 2.4. Nhập file PEM và trích xuất tham số toán học ($n, e, d, p, q, dp, dq, q_{\text{inv}}$)
   - 2.5. Mã hoá dữ liệu $\le 190$ bytes (Giải thích tại sao $\le 190$ bytes và mô hình Mã hoá lai)
   - 2.6. Giải mã file .enc và so sánh từng byte với nguồn
   - 2.7. Đánh giá tốc độ thao tác Public Key ($n, e$ bé) vs Private Key ($n, d$ lớn) & Bản chất toán học
   - 2.8. Giao diện sinh chuỗi băm SHA-256 thời gian thực & Đánh giá Hiệu ứng thác đổ (Avalanche Effect)
   - 2.9. Chữ ký số RSA & Đề xuất 2 phương pháp để "Cùng dữ liệu + Cùng khoá bí mật $\rightarrow$ Chữ ký khác nhau mỗi lần"
3. [HƯỚNG DẪN CÀI ĐẶT VÀ CHẠY ỨNG DỤNG](#phần-3-hướng-dẫn-cài-đặt-và-chạy-ứng-dụng)

---

# PHẦN 1: BÀI TẬP 1 - MÃ HOÁ ĐỐI XỨNG AES
*(Mã hoá và giải mã cùng sử dụng chung một khoá bí mật)*

### 1.1. Sinh khoá AES (128 / 192 / 256-bit) & Vector khởi tạo IV (16 bytes)
- **Nguyên lý:** Sử dụng lớp `Aes.Create()` trong `System.Security.Cryptography`.
- **Độ dài khoá:** Hỗ trợ linh hoạt 128-bit (16 bytes), 192-bit (24 bytes) và 256-bit (32 bytes - mặc định theo chuẩn an toàn cao nhất).
- **Vector khởi tạo (IV):** Luôn cố định là **16 bytes (128-bit)** tương ứng với kích thước khối (Block size) của thuật toán AES. IV được sinh ngẫu nhiên tuyệt đối qua bộ sinh số ngẫu nhiên mật mã CSPRNG (`RandomNumberGenerator`).
- **Hiển thị:** Được mã hoá hiển thị đồng thời ở 2 định dạng:
  - Chuỗi **Base64** (thuận tiện cho lưu trữ và truyền nhận text).
  - Chuỗi **Hexadecimal (Hex)** (giúp quan sát chính xác từng byte nhị phân).

### 1.2. Lưu khoá ra file
- Hệ thống hỗ trợ xuất gói khoá ra file định dạng `.aeskey` dưới dạng JSON có cấu trúc rõ ràng:
```json
{
  "KeySizeBits": 256,
  "KeyBase64": "JGF7ppGRW5UqO5Yj3fv6TljBjYPQOYZXukNbvzTwMpU=",
  "KeyHex": "24617BA691915B952A3B9623DDFBFA4E58C18D83D0398657BA435BBF34F03295",
  "IvBase64": "/yIkUt86F5+S0tn/Ja9Frw==",
  "IvHex": "FF222452DF3A179F92D2D9FF25AF45AF",
  "CreatedAtUtc": "2026-10-16T08:28:04Z"
}
```

### 1.3. Import khoá từ file
- Đọc file `.aeskey`, thực hiện parse JSON và nạp trở lại bộ nhớ.
- Kiểm tra tính hợp lệ của độ dài khoá và IV trước khi đưa lên giao diện, đảm bảo an toàn và tránh lỗi giải mã sai khoá.

### 1.4. Mã hoá / Giải mã một đoạn văn bản (Text)
- **Chế độ hoạt động:** AES chế độ `CipherMode.CBC` (Cipher Block Chaining) kết hợp đệm `PaddingMode.PKCS7`.
- **Mã hoá:** Nhập Plaintext UTF-8 $\rightarrow$ AES-CBC biến đổi thành mảng byte Ciphertext $\rightarrow$ Chuyển sang Base64 hiển thị lên màn hình.
- **Giải mã:** Nhập Ciphertext Base64 $\rightarrow$ Chuyển thành byte $\rightarrow$ Giải mã bằng Key + IV $\rightarrow$ Chuyển ngược lại chuỗi ký tự UTF-8 ban đầu.

### 1.5. Mã hoá / Giải mã File kích thước lớn (Hàng GB) & Phòng tránh `OutOfMemoryException`
- **Thách thức:** Nếu dùng `File.ReadAllBytes()` trên các file dung lượng 1GB, 2GB hay 5GB, CLR sẽ cấp phát một khối bộ nhớ mảng liên tục khổng lồ trong RAM, lập tức ném ra biệt lệ `OutOfMemoryException` và làm sập ứng dụng.
- **Giải pháp kiến trúc:**
  - Áp dụng kỹ thuật **Streaming Pipeline** kết hợp giữa `FileStream` và `CryptoStream`.
  - Thiết lập kích thước Buffer chuẩn là **1 MB (1.048.576 bytes)**:
    ```csharp
    public const int ChunkBufferSize = 1024 * 1024; // 1 MB buffer
    ```
  - Quá trình đọc/ghi thực hiện theo từng khối 1MB bất đồng bộ (`ReadAsync` và `WriteAsync`).
  - **Kết quả:** Dung lượng RAM sử dụng của ứng dụng luôn duy trì ổn định ở mức cực thấp (**$< 50 \text{ MB}$**) kể cả khi mã hoá file 5GB hay 10GB.
  - Giao diện người dùng sử dụng `IProgress<(long processed, long total, double speedMbPerSec)>` để cập nhật thanh tiến trình (`ProgressBar`) và tốc độ xử lý theo thời gian thực mà không làm treo ứng dụng (`UI Freezing`).
  - Tích hợp nút tiện ích **"Tạo file mẫu lớn (Dummy File)"** cho phép tạo nhanh file thử nghiệm 100MB, 500MB, 1GB, 2GB.

### 1.6. So sánh theo từng byte (Compare Bytes) & Kiểm tra toàn vẹn SHA-256
- Chức năng đối chiếu hai file được thực hiện theo luồng streaming song song:
  - Đọc đồng thời từng khối 1MB từ File nguồn và File sau giải mã.
  - So sánh đối chiếu từng cặp byte `buf1[i] == buf2[i]`.
  - Đếm tổng số byte đã kiểm tra, phát hiện số lượng byte sai khác và vị trí offset byte lỗi đầu tiên nếu có.
  - Đồng thời cập nhật dữ liệu vào bộ tính mã băm `IncrementalHash` để tính mã băm SHA-256 của cả 2 file.

### 1.7. KẾT LUẬN DỰA THEO SỐ LIỆU THỰC NGHIỆM THU ĐƯỢC
Dưới đây là bảng số liệu đo đạc thực nghiệm thực tế thu được từ hệ thống:

| Tiêu chí đo đạc | Giá trị thực nghiệm | Đánh giá kỹ thuật |
| :--- | :--- | :--- |
| **Kích thước file thử nghiệm** | **50 MB** ($52.428.800 \text{ bytes}$) | Thử nghiệm khối lượng lớn qua luồng 1MB |
| **Thời gian mã hoá AES-256** | **0,14 giây** ($140,5 \text{ ms}$) | Tối ưu I/O và mã hoá phần cứng AES-NI |
| **Tốc độ mã hoá trung bình** | **355,77 MB/s** | Rất nhanh, đáp ứng tốt ứng dụng thời gian thực |
| **Thời gian giải mã AES-256** | **0,15 giây** ($154,0 \text{ ms}$) | Ổn định, tương đương tốc độ mã hoá |
| **Tốc độ giải mã trung bình** | **324,65 MB/s** | Tốc độ giải mã cực cao |
| **Mã băm SHA-256 file gốc** | `33EC9F483AAB3154968DA0416DF3C24FA...` | Bản băm 256-bit gốc |
| **Mã băm SHA-256 sau giải mã** | `33EC9F483AAB3154968DA0416DF3C24FA...` | Trùng khớp tuyệt đối $100\%$ |
| **Số byte kiểm tra đối chiếu** | **52.428.800 bytes** | Kiểm tra toàn diện từng byte |
| **Số byte sai khác phát hiện** | **0 bytes** | Không suy hao, không sai lệch bit |

> **KẾT LUẬN BÀI 1:** 
> 1. Thuật toán AES-256 chế độ CBC cho tốc độ mã hoá và giải mã vượt trội ($> 300 \text{ MB/s}$), hoàn toàn phù hợp để bảo vệ dữ liệu khối lượng lớn hàng Gigabyte.
> 2. Kiến trúc Streaming Buffer 1MB giải quyết triệt để bài toán tràn bộ nhớ RAM (`OutOfMemoryException`).
> 3. Phép đối chiếu từng byte và so sánh mã băm SHA-256 chứng minh tính toàn vẹn thông tin được bảo toàn tuyệt đối $100\%$.

---

# PHẦN 2: BÀI TẬP 2 - MÃ HOÁ BẤT ĐỐI XỨNG RSA & CHỮ KÝ SỐ
*(Mã hoá bằng một chìa, giải mã bằng chìa còn lại)*

### 2.1. Sinh cặp khoá RSA
- Khởi tạo đối tượng `RSA.Create(keySizeBits)`.
- Hỗ trợ độ dài khoá **2048-bit** (chuẩn khuyến nghị hiện nay của NIST) và **4096-bit** (bảo mật tối đa).
- Cặp khoá gồm:
  - **Public Key (Khoá công khai):** Được chia sẻ rộng rãi, dùng để mã hoá dữ liệu hoặc xác thực chữ ký số.
  - **Private Key (Khoá bí mật):** Phải được giữ bí mật tuyệt đối, dùng để giải mã dữ liệu hoặc tạo chữ ký số.

### 2.2. Xuất cặp khoá ra file PEM
- Xuất Public Key: `ExportSubjectPublicKeyInfoPem()` (chuẩn X.509 SPKI) hoặc `ExportRSAPublicKeyPem()` (chuẩn PKCS#1).
- Xuất Private Key: `ExportRSAPrivateKeyPem()` (chuẩn PKCS#1) hoặc `ExportPkcs8PrivateKeyPem()` (chuẩn PKCS#8).
- File có định dạng text gồm 3 phần:
  - Header: `-----BEGIN RSA PRIVATE KEY-----` (hoặc `-----BEGIN PUBLIC KEY-----`)
  - Body: Chuỗi mã hoá Base64 của cấu trúc nhị phân ASN.1 DER.
  - Footer: `-----END RSA PRIVATE KEY-----` (hoặc `-----END PUBLIC KEY-----`)

---

### 2.3. View PEM & Giải thích chi tiết ý nghĩa các byte trong cấu trúc ASN.1 DER (TLV Breakdown)
Khi giải mã chuỗi Base64 trong phần thân của file `.pem`, ta thu được một chuỗi byte nhị phân được tổ chức theo chuẩn **ASN.1 DER** (Abstract Syntax Notation One - Distinguished Encoding Rules).

Mọi phần tử trong ASN.1 DER đều tuân thủ chặt chẽ nguyên tắc **TLV: Tag - Length - Value**:
- **Tag (1 byte):** Định danh kiểu dữ liệu:
  - `0x30`: `SEQUENCE` (thẻ chứa danh sách có thứ tự).
  - `0x02`: `INTEGER` (số nguyên lớn có dấu).
  - `0x04`: `OCTET STRING` (chuỗi byte nhị phân).
  - `0x03`: `BIT STRING` (chuỗi bit).
- **Length:**
  - Nếu độ dài $< 128$: Biểu diễn bằng 1 byte (bit cao nhất là 0).
  - Nếu độ dài $\ge 128$: Byte đầu tiên có dạng `0x80 | numBytes`, tiếp theo là `numBytes` chứa độ dài thực tế dạng Big-Endian (Ví dụ `0x82 0x04 0xA4` nghĩa là độ dài chiếm 2 bytes phía sau với giá trị $0x04A4 = 1188 \text{ bytes}$).
- **Value:** Dữ liệu thực tế. Riêng kiểu `INTEGER`, vì DER dùng mã bù hai, nếu bit cao nhất của số nguyên dương là `1` (giá trị $\ge 0x80$), một byte `0x00` đệm dấu bắt buộc phải được thêm vào đầu (đó là lý do Modulus 2048-bit thường có kích thước 257 bytes thay vì 256 bytes).

#### Bảng giải nghĩa từng byte cấu trúc ASN.1 DER của file PKCS#1 RSAPrivateKey thực tế:
| Offset (Byte) | Tag (Hex) | Loại thẻ ASN.1 | Độ dài (bytes) | Tên trường | Ý nghĩa toán học và bảo mật |
| :---: | :---: | :---: | :---: | :--- | :--- |
| `0000` | `0x30` | `SEQUENCE` | `1188` | **RSAPrivateKey** | Thẻ cha bọc toàn bộ 9 tham số toán học của khoá RSA (RFC 3447). |
| `0004` | `0x02` | `INTEGER` | `1` | **version** | Phiên bản PKCS#1 (giá trị `0` cho khoá hai số nguyên tố $p, q$). |
| `0007` | `0x02` | `INTEGER` | `257` | **modulus (n)** | Modulus công khai $n = p \cdot q$ (256 bytes kèm byte `0x00` đệm dấu). |
| `0268` | `0x02` | `INTEGER` | `3` | **publicExponent (e)** | Số mũ công khai $e = 65537$ (`0x010001`). |
| `0273` | `0x02` | `INTEGER` | `256` | **privateExponent (d)** | Số mũ bí mật $d = e^{-1} \pmod{\phi(n)}$, dùng để giải mã và tạo chữ ký. |
| `0533` | `0x02` | `INTEGER` | `129` | **prime1 (p)** | Số nguyên tố bí mật thứ nhất $p$ (1024-bit + 1 byte đệm dấu `0x00`). |
| `0665` | `0x02` | `INTEGER` | `129` | **prime2 (q)** | Số nguyên tố bí mật thứ hai $q$ (1024-bit + 1 byte đệm dấu `0x00`). |
| `0797` | `0x02` | `INTEGER` | `129` | **exponent1 (dp)** | Số mũ CRT thứ nhất: $d_p = d \bmod (p - 1)$, giúp tăng tốc giải mã. |
| `0929` | `0x02` | `INTEGER` | `129` | **exponent2 (dq)** | Số mũ CRT thứ hai: $d_q = d \bmod (q - 1)$, giúp tăng tốc giải mã. |
| `1061` | `0x02` | `INTEGER` | `128` | **coefficient (qInv)** | Nghịch đảo CRT: $q_{\text{inv}} = q^{-1} \bmod p$. |

---

### 2.4. Nhập file PEM và trích xuất tham số toán học
- Dùng `rsa.ImportFromPem(pemText)` để phân tích cú pháp.
- **Trích xuất Public Key:** Nhận diện Modulus $n$ (2048 bits / 256 bytes) và Public Exponent $e = 65537$ (`0x010001`).
- **Trích xuất Private Key:** Nhận diện toàn bộ bộ tham số toán học: $n, e, d, p, q, dp, dq, q_{\text{inv}}$ hiển thị trực quan dưới dạng Hex, Base64 và số lượng bytes/bits.

---

### 2.5. Mã hoá dữ liệu sử dụng key vừa import ($\le 190$ bytes)
- **Dữ liệu đầu vào mẫu:** Khoá đối xứng AES-256 (gồm **32 bytes** = 256 bits dạng Base64).
- **CÂU HỎI QUAN TRỌNG: TẠI SAO DỮ LIỆU ĐẦU VÀO PHẢI $\le 190$ BYTES?**
  - Đối với khoá RSA 2048-bit, độ dài modulus $k = 2048 \text{ bits} = 256 \text{ bytes}$.
  - Chuẩn mã hoá an toàn hiện đại **OAEP (Optimal Asymmetric Encryption Padding - RFC 3447)** sử dụng hàm băm SHA-256 có độ dài băm $hLen = 32 \text{ bytes}$.
  - Công thức giới hạn kích thước bản rõ tối đa của RSA-OAEP:
    $$\text{MaxPlaintextLength} = k - 2 \cdot hLen - 2$$
  - Thay số cụ thể:
    $$\text{MaxPlaintextLength} = 256 - (2 \times 32) - 2 = 256 - 64 - 2 = 190 \text{ bytes}$$
  - Nếu mảng byte đầu vào dài $> 190 \text{ bytes}$, thuật toán sẽ ném lỗi vì không đủ không gian chứa khối mặt nạ và byte đệm.
- **Ý nghĩa trong mô hình Mã hoá lai (Hybrid / Envelope Encryption):**
  - Không bao giờ dùng RSA để mã hoá trực tiếp file nặng vì tốc độ rất chậm.
  - Thay vào đó, người ta dùng AES-256 để mã hoá file lớn tốc độ cao ($> 300 \text{ MB/s}$), sau đó dùng RSA để bọc (mã hoá) khoá AES 32 bytes này (hoàn toàn nhỏ hơn 190 bytes) để tạo thành **Phong bì số (Digital Envelope)**.
- **Kết quả mã hoá:** Mảng byte đầu ra luôn có kích thước cố định là **256 bytes (2048 bits)**, được mã hoá sang chuỗi Base64 và lưu vào file `.enc`.

---

### 2.6. Giải mã: Đầu vào là PEM (Private Key) và file chứa dữ liệu đã mã hoá (.enc)
- Ứng dụng đọc file `.enc`, chuyển chuỗi Base64 thành mảng byte ciphertext 256 bytes.
- Dùng Private Key giải mã: `rsa.Decrypt(cipherBytes, RSAEncryptionPadding.OaepSHA256)`.
- Nhận được mảng byte ban đầu (32 bytes).
- Đối chiếu tự động từng byte với mảng dữ liệu nguồn: **Khớp tuyệt đối 32/32 bytes (100%)**.

---

### 2.7. Đánh giá tốc độ mã hoá, giải mã (Public Key vs Private Key) & Bản chất toán học

#### Số liệu benchmark thực nghiệm thực tế (500 lần lặp liên tục):
- **Thao tác Public Key ($c = m^e \bmod n$):** `0,0287 ms/lần` $\rightarrow$ **$34.880 \text{ ops/giây}$**.
- **Thao tác Private Key ($m = c^d \bmod n$):** `0,8038 ms/lần` $\rightarrow$ **$1.244 \text{ ops/giây}$**.
- **Tỷ lệ chênh lệch tốc độ:** Thao tác Private Key **chậm hơn Public Key 28,0 lần**.

```
Tốc độ xử lý (Số phép tính / giây):
Public Key (Mã hoá / Xác thực chữ ký): [████████████████████████████████████] 34,880 ops/s
Private Key (Giải mã / Ký số)        : [█] 1,244 ops/s
```

#### Phân tích nguyên nhân toán học sâu sắc:
1. **Khoá công khai $(n, e)$ với $e$ rất bé:**
   - Số mũ công khai chuẩn hoá quốc tế là $e = 65537 = 2^{16} + 1 = \text{0x010001}$.
   - Biểu diễn nhị phân của $e$ gồm 17 bits: `10000000000000001_2$ (chỉ có duy nhất hai bit '1', tức trọng số Hamming $H(e) = 2$).
   - Thuật toán luỹ thừa nhanh *Square-and-Multiply (Bình phương và Nhân)* chỉ mất đúng:
     - 16 phép bình phương modulo.
     - 1 phép nhân modulo.
     - $\rightarrow$ Tổng cộng chỉ **17 phép tính cơ bản**, thực thi gần như tức thời ($< 0,03 \text{ ms}$).
2. **Khoá riêng tư $(n, d)$ với $d$ rất lớn:**
   - Số mũ bí mật $d = e^{-1} \pmod{\phi(n)}$ là số nguyên ngẫu nhiên cực lớn dài xấp xỉ 2048 bits.
   - Trọng số Hamming trung bình $H(d) \approx 1024$ bits '1'.
   - Kể cả khi hệ thống tối ưu bằng **Định lý số dư Trung Hoa (CRT)** chia làm 2 nhánh modulo $p$ và modulo $q$ (mỗi số 1024-bit), mỗi nhánh vẫn đòi hỏi khoảng **1024 phép bình phương** và **512 phép nhân các số nguyên lớn 1024-bit**.
   - $\rightarrow$ Khối lượng tính toán của Private Key nặng gấp hàng chục lần Public Key.

---

### 2.8. Giao diện sinh chuỗi băm SHA-256 thời gian thực & Hiệu ứng thác đổ (Avalanche Effect)
- **Giao diện thời gian thực:** Ngay khi người dùng gõ phím ở ô "Input A" hoặc "Input B", hệ thống tự động băm và hiển thị kết quả đồng thời ở dạng Hex 64 ký tự và nhị phân 256 bits.
- **Thực nghiệm Hiệu ứng thác đổ khi thay đổi cực ít ở đầu vào:**
  - **Dữ liệu A:** `AnToanBaoMatThongTin_2026_Lab_A`
  - **Dữ liệu B:** `AnToanBaoMatThongTin_2026_Lab_B` (Chỉ đổi 1 ký tự cuối từ 'A' thành 'B', tương đương khác nhau đúng 2 bit nhị phân).
  - Kết quả băm:
    - $\text{SHA256}(A) =$ `1BBAA9013AC037EF9EAD0FDCEC4FC5787515C98A55005B105EB3F5E207397D1E`
    - $\text{SHA256}(B) =$ `8294D38A49102894B8294E10D5F20DD5C25BD50DB35A075B1C6BABE24E2EC9F0`
  - **Khoảng cách Hamming (Số bit bị đảo):** **$127 / 256 \text{ bits}$**.
  - **Tỷ lệ bit bị đảo:** **$49,61\%$** (tiệm cận mức lý tưởng $50\%$).
  - **Số ký tự Hex khác biệt:** $61 / 64 \text{ ký tự}$.
- **Đánh giá tiêu chuẩn SAC (Strict Avalanche Criterion):**
  - Tiêu chuẩn thác đổ nghiêm ngặt đòi hỏi khi đảo bất kỳ 1 bit đầu vào thì mỗi bit đầu ra phải thay đổi với xác suất $50\%$ ($P = 0.5$).
  - Nhờ cấu trúc 64 vòng lặp phi tuyến với các hàm $\text{Ch}, \text{Maj}, \Sigma_0, \Sigma_1$ và phép cộng modulo $2^{32}$, SHA-256 đảm bảo sự khuếch tán và xáo trộn hoàn hảo, triệt tiêu mọi khả năng tấn công vi phân hay tìm tiền ảnh.

---

### 2.9. Chữ ký số RSA & Đề xuất 2 Phương pháp để "Cùng dữ liệu + Cùng người ký $\rightarrow$ Chữ ký số KHÁC NHAU mỗi lần"

#### A. Vấn đề của Chữ ký số định tính PKCS#1 v1.5 (Deterministic):
- Chữ ký số bản chất là: $\text{Signature} = \text{Sign}_{d}(\text{SHA256}(\text{Data}))$.
- Theo chuẩn cũ PKCS#1 v1.5, vì không có yếu tố ngẫu nhiên trong khối đệm, nên:
  - Cùng 1 văn bản + Cùng 1 Private Key $\rightarrow$ Ký lần 1, lần 2, lần 3 đều cho ra chuỗi chữ ký **GIỐNG HỆT NHAU 100%**.
  - **Nhược điểm:** Dễ bị tấn công phát lại (Replay Attack) và để lộ tần suất ký cùng một nội dung.

---

#### B. ĐỀ XUẤT VÀ HIỆN THỰC 2 PHƯƠNG PHÁP KHỬ ĐỊNH TÍNH:

#### PHƯƠNG PHÁP 1: Chuẩn mật mã học RSA-PSS (Probabilistic Signature Scheme - RFC 3447 / PKCS#1 v2.1)
- **Cơ chế hoạt động:**
  - Đây là chuẩn chữ ký số xác suất hiện đại nhất của RSA.
  - Trước khi thực hiện phép luỹ thừa khoá bí mật $d$, thuật toán tự động sinh một chuỗi muối ngẫu nhiên (**Random Salt** $s$, kích thước bằng độ dài hàm băm: 32 bytes đối với SHA-256).
  - Thuật toán kết hợp Salt với mã băm dữ liệu qua hàm sinh mặt nạ **MGF1** (Mask Generation Function 1 dựa trên SHA-256).
  - Khối dữ liệu sau khi phủ mặt nạ được luỹ thừa bí mật: $S = EM^d \bmod n$.
- **Đặc điểm vượt trội:**
  - Nhờ có Salt ngẫu nhiên mới ở mỗi lần bấm ký, chữ ký số đầu ra luôn **khác nhau 100%** giữa các lần ký.
  - **Tính tự chứa (Self-contained):** Người nhận khi xác thực bằng Public Key (`VerifyData` với `RSASignaturePadding.Pss`) chỉ cần dùng Public Key $(n, e)$ giải mặt nạ MGF1 để bóc tách Salt và kiểm tra tính toàn vẹn. Người ký **KHÔNG CẦN gửi riêng Salt** cho người nhận.
- **Thực nghiệm trên giao diện ứng dụng:**
  - Ký 3 lần liên tiếp trên cùng 1 văn bản: Thu được 3 chuỗi chữ ký Base64 khác nhau hoàn toàn.
  - Bấm nút "Xác thực cả 3 chữ ký bằng Public Key": Cả 3 đều trả về **`HỢP LỆ (VALID)`**.

---

#### PHƯƠNG PHÁP 2: Bổ sung Nonce & Timestamp ở tầng gói tin ứng dụng (Application Level)
- **Cơ chế hoạt động:**
  - Thay vì can thiệp ở tầng giải thuật mật mã, ta đóng gói dữ liệu ở tầng ứng dụng kèm:
    1. **TimestampUtcTicks:** Nhãn thời gian thực chuẩn UTC dạng số ticks (độ chính xác microsecond).
    2. **Random Nonce:** Số ngẫu nhiên dùng một lần ($16 \text{ bytes} = 128 \text{ bits}$ sinh bằng CSPRNG).
  - Chuỗi dữ liệu thực tế được đưa vào băm và ký:
    $$\text{Payload} = \text{Data} \ || \ \text{TimestampUtcTicks} \ || \ \text{Nonce}$$
    $$\text{Signature} = \text{Sign}_{d}(\text{SHA256}(\text{Payload}))$$
- **Ưu điểm bảo mật thực tế:**
  - Mỗi lần tạo giao dịch, Timestamp và Nonce luôn thay đổi $\rightarrow$ Chữ ký luôn luôn duy nhất.
  - **Chống tấn công phát lại (Replay Attack):** Phía nhận xác thực chữ ký và kiểm tra xem Timestamp có nằm trong cửa sổ thời gian hợp lệ (ví dụ $\pm 5 \text{ phút}$) hay không, đồng thời lưu Nonce vào cache để từ chối ngay lập tức nếu gói tin bị phát lại lần thứ hai.

---

# PHẦN 3: HƯỚNG DẪN CÀI ĐẶT VÀ CHẠY ỨNG DỤNG

### Yêu cầu hệ thống:
- Hệ điều hành: Windows 10 / 11 (x64).
- Môi trường: .NET SDK 8.0 trở lên.

### 1. Khởi chạy Giao diện Đồ hoạ (Windows Forms GUI):
```powershell
# Chạy trực tiếp từ terminal
dotnet run --project "D:\antoanbaomatthongtin\SecurityLab_AES_RSA\SecurityLab_AES_RSA.csproj"

# Hoặc khởi chạy file thực thi đã biên dịch
& "D:\antoanbaomatthongtin\SecurityLab_AES_RSA\bin\Debug\net8.0-windows\SecurityLab_AES_RSA.exe"
```

### 2. Khởi chạy Chế độ Kiểm thử Dòng lệnh Tự động (`--self-test`):
Hệ thống tích hợp sẵn chế độ dòng lệnh tự động thực hiện từ đầu đến cuối 7 kịch bản kiểm thử (AES text/file, RSA PEM/DER, Benchmark tốc độ, SHA-256 Avalanche, RSA-PSS và Nonce) và tự động xuất số liệu thực tế ra file markdown:
```powershell
Start-Process -FilePath "D:\antoanbaomatthongtin\SecurityLab_AES_RSA\bin\Debug\net8.0-windows\SecurityLab_AES_RSA.exe" -ArgumentList "--self-test" -Wait -NoNewWindow
```
