# BÁO CÁO THỰC NGHIỆM VÀ PHÂN TÍCH LÝ THUYẾT MÔN AN TOÀN VÀ BẢO MẬT THÔNG TIN
## ĐỀ TÀI: MÃ HOÁ ĐỐI XỨNG AES, MÃ HOÁ BẤT ĐỐI XỨNG RSA, HÀM BĂM SHA-256 & CHỮ KÝ SỐ

- **Họ và tên / Vai trò:** Chuyên gia An toàn thông tin & Kỹ sư Phần mềm .NET
- **Công nghệ triển khai:** C# / .NET 8.0 (Windows Forms), Kiến trúc Bất đồng bộ (`async/await`)
- **Dự án thực nghiệm:** `SecurityLab_AES_RSA`
- **Môi trường đo lường:** Windows 10/11 x64, .NET SDK 8.0

---

## MỤC LỤC
1. [BÀI 1: MÃ HOÁ ĐỐI XỨNG AES (ADVANCED ENCRYPTION STANDARD)](#1-bài-1-mã-hoá-đối-xứng-aes)
   - 1.1. Lý thuyết kiến trúc AES, chế độ CBC và đệm PKCS7
   - 1.2. Kỹ thuật Streaming Buffer 1MB xử lý file hàng GB phòng ngừa OutOfMemoryException
   - 1.3. Số liệu thực nghiệm mã hoá / giải mã file và kiểm tra toàn vẹn từng byte
2. [BÀI 2: MÃ HOÁ BẤT ĐỐI XỨNG RSA & PHÂN TÍCH PEM](#2-bài-2-mã-hoá-bất-đối-xứng-rsa--phân-tích-pem)
   - 2.1. Cặp khoá RSA và các tham số toán học cơ bản
   - 2.2. Phân tích chuyên sâu cấu trúc byte PEM & cây ASN.1 DER (TLV Breakdown)
   - 2.3. Ràng buộc kích thước dữ liệu $\le 190$ bytes (RSA-2048 OAEP-SHA256) và Mã hoá lai (Hybrid Encryption)
   - 2.4. Đánh giá tốc độ thao tác Public Key vs Private Key và Nguyên nhân toán học
3. [BÀI 2 (Ý 8): HÀM BĂM SHA-256 & HIỆU ỨNG THÁC ĐỔ (AVALANCHE EFFECT)](#3-bài-2-ý-8-hàm-băm-sha-256--hiệu-ứng-thác-đổ)
   - 3.1. Cấu trúc 64 vòng lặp của SHA-256
   - 3.2. Tiêu chuẩn thác đổ nghiêm ngặt (Strict Avalanche Criterion - SAC)
   - 3.3. Số liệu thực nghiệm đo khoảng cách Hamming và tỷ lệ đảo bit
4. [BÀI 2 (Ý 9): CHỮ KÝ SỐ RSA & CƠ CHẾ SINH CHỮ KÝ KHÁC NHAU CHO CÙNG DỮ LIỆU](#4-bài-2-ý-9-chữ-ký-số-rsa--cơ-chế-sinh-chữ-ký-khác-nhau)
   - 4.1. Chữ ký số định tính PKCS#1 v1.5 (Deterministic)
   - 4.2. Phương pháp 1: Chuẩn mật mã học RSA-PSS (Probabilistic Signature Scheme - PKCS#1 v2.1)
   - 4.3. Phương pháp 2: Bổ sung Nonce & Timestamp ở tầng gói tin ứng dụng
5. [KẾT LUẬN TỔNG THỂ](#5-kết-luận-tổng-thể)

---

## 1. BÀI 1: MÃ HOÁ ĐỐI XỨNG AES

### 1.1. Lý thuyết kiến trúc AES, chế độ CBC và đệm PKCS7
- **Thuật toán AES (Rijndael):** Là chuẩn mã hoá khối (Block Cipher) đối xứng được NIST ban hành năm 2001. Kích thước khối dữ liệu chuẩn luôn cố định là $128 \text{ bits}$ ($16 \text{ bytes}$). Độ dài khoá hỗ trợ $128, 192$, hoặc $256 \text{ bits}$ tương ứng với $10, 12$, hoặc $14$ vòng biến đổi (Rounds). Mỗi vòng bao gồm 4 phép biến đổi đại số trên trường hữu hạn $GF(2^8)$:
  1. `SubBytes`: Thay thế phi tuyến từng byte qua bảng S-box.
  2. `ShiftRows`: Dịch vòng các hàng trong ma trận trạng thái $4 \times 4$.
  3. `MixColumns`: Khuếch tán dữ liệu theo cột thông qua phép nhân ma trận.
  4. `AddRoundKey`: Cộng XOR ma trận trạng thái với khoá con sinh ra từ thuật toán Key Schedule.

- **Chế độ Cipher Block Chaining (CBC):**
  - Công thức mã hoá: $C_i = E_K(P_i \oplus C_{i-1})$ với $C_0 = IV$ (Initialization Vector).
  - Công thức giải mã: $P_i = D_K(C_i) \oplus C_{i-1}$ với $C_0 = IV$.
  - **Vector khởi tạo (IV):** Phải có độ dài đúng $16 \text{ bytes}$ (bằng kích thước khối AES) và được sinh ngẫu nhiên bằng bộ sinh số giả ngẫu nhiên mật mã (`RandomNumberGenerator`). IV không cần giữ bí mật nhưng bắt buộc phải là duy nhất cho mỗi phiên mã hoá để ngăn chặn tấn công nhận dạng bản rõ giống nhau.

- **Quy tắc đệm PKCS#7 (Padding):**
  - Vì AES hoạt động theo từng khối $16 \text{ bytes}$, nếu khối cuối cùng có độ dài $L < 16$, thuật toán sẽ bổ sung $N = 16 - (L \bmod 16)$ bytes, mỗi byte có giá trị chính bằng số nguyên $N$. Nếu dữ liệu chia hết cho 16, thuật toán vẫn thêm một khối đệm đầy đủ gồm 16 bytes giá trị `0x10` để tránh nhập nhằng khi bóc đệm.

### 1.2. Kỹ thuật Streaming Buffer 1MB xử lý file hàng GB phòng ngừa OutOfMemoryException
- **Vấn đề bộ nhớ:** Nếu sử dụng phương thức thông thường như `File.ReadAllBytes()` trên file dung lượng lớn (1 GB – 5 GB), ứng dụng sẽ cấp phát một mảng byte liên tục khổng lồ trong bộ nhớ heap của CLR, nhanh chóng dẫn đến lỗi `OutOfMemoryException` và làm treo toàn bộ ứng dụng.
- **Giải pháp kiến trúc:**
  - Ứng dụng triển khai luồng truyền dữ liệu liên tục (`Streaming Pipeline`) sử dụng `FileStream` kết hợp với `CryptoStream`.
  - Buffer kích thước chuẩn được thiết lập là $1 \text{ MB} = 1.048.576 \text{ bytes}$.
  - Vòng lặp đọc/ghi bất đồng bộ (`ReadAsync` và `WriteAsync`) kèm báo cáo tiến độ `IProgress` giúp giao diện Windows Forms không bị đóng băng (`UI Freezing`), đồng thời dung lượng RAM tiêu thụ duy trì ổn định ở mức $< 50 \text{ MB}$ bất kể kích thước file nguồn lên tới $5 \text{ GB}$ hay $10 \text{ GB}$.

### 1.3. Số liệu thực nghiệm mã hoá / giải mã file và kiểm tra toàn vẹn từng byte
Dưới đây là số liệu đo đạc thực tế thu được từ quá trình kiểm thử tự động của hệ thống:
- **Kích thước file thử nghiệm:** $50 \text{ MB} = 52.428.800 \text{ bytes}$.
- **Khoá AES-256 (Hex):** `24617BA691915B952A3B9623DDFBFA4E58C18D83D0398657BA435BBF34F03295`
- **Vector khởi tạo IV (Hex):** `FF222452DF3A179F92D2D9FF25AF45AF`
- **Thời gian mã hoá:** $0,14 \text{ giây}$ ($140,5 \text{ ms}$) $\rightarrow$ **Tốc độ mã hoá:** $355,77 \text{ MB/s}$.
- **Thời gian giải mã:** $0,15 \text{ giây}$ ($154,0 \text{ ms}$) $\rightarrow$ **Tốc độ giải mã:** $324,65 \text{ MB/s}$.
- **Mã băm SHA-256 file nguồn:** `33EC9F483AAB3154968DA0416DF3C24FA2FDA7FEE970CF764EE548B2FEB911CC`
- **Mã băm SHA-256 sau giải mã:** `33EC9F483AAB3154968DA0416DF3C24FA2FDA7FEE970CF764EE548B2FEB911CC`
- **Đối chiếu từng byte (Byte-by-byte compare):**
  - Tổng số byte quét qua: $52.428.800 \text{ bytes}$.
  - Số lượng byte sai khác: $0 \text{ byte}$.
  - **Kết luận:** File sau giải mã bảo toàn tính toàn vẹn tuyệt đối $100\%$ so với file gốc ban đầu.

---

## 2. BÀI 2: MÃ HOÁ BẤT ĐỐI XỨNG RSA & PHÂN TÍCH PEM

### 2.1. Cặp khoá RSA và các tham số toán học cơ bản
Hệ mật RSA dựa trên độ khó của bài toán phân tích một hợp số lớn thành tích hai số nguyên tố (Integer Factorization Problem):
1. **Hai số nguyên tố lớn:** $p$ và $q$ (khoảng 1024-bit mỗi số đối với RSA-2048).
2. **Modulus công khai:** $n = p \times q$. Không gian tin nhắn và bản mã nằm trong $\mathbb{Z}_n$.
3. **Hàm Euler:** $\phi(n) = (p - 1)(q - 1)$.
4. **Số mũ công khai:** $e$ thoả mãn $\gcd(e, \phi(n)) = 1$. Giá trị chuẩn quốc tế thường chọn là $e = 65537 = 2^{16} + 1 = \text{0x010001}$.
5. **Số mũ bí mật:** $d = e^{-1} \pmod{\phi(n)}$, tức $e \cdot d \equiv 1 \pmod{\phi(n)}$.
6. **Các tham số CRT (Chinese Remainder Theorem) giúp tăng tốc giải mã:**
   - $d_p = d \bmod (p - 1)$
   - $d_q = d \bmod (q - 1)$
   - $q_{\text{inv}} = q^{-1} \bmod p$

### 2.2. Phân tích chuyên sâu cấu trúc byte PEM & cây ASN.1 DER (TLV Breakdown)
File định dạng `.pem` (Privacy-Enhanced Mail) thực chất là cấu trúc nhị phân được mã hoá theo chuẩn **ASN.1 DER** (Abstract Syntax Notation One - Distinguished Encoding Rules) và bọc ngoài bằng mã hoá Base64 kèm Header (`-----BEGIN ...-----`) và Footer (`-----END ...-----`).

Quy tắc mã hoá ASN.1 DER tuân theo nguyên lý **TLV (Tag - Length - Value)**:
- **Tag (1 byte):** Xác định kiểu dữ liệu.
  - `0x30`: `SEQUENCE` (Cấu trúc danh sách các phần tử phức hợp).
  - `0x02`: `INTEGER` (Số nguyên lớn có dấu).
  - `0x04`: `OCTET STRING` (Chuỗi byte nhị phân).
  - `0x03`: `BIT STRING` (Chuỗi bit).
- **Length:**
  - Nếu độ dài $< 128$: Biểu diễn bằng 1 byte (bit cao nhất bằng `0`).
  - Nếu độ dài $\ge 128$: Byte đầu tiên có dạng `0x80 | numBytes`, theo sau là `numBytes` chứa giá trị độ dài dạng Big-Endian. Ví dụ `0x82 0x04 0xA4` nghĩa là độ dài được biểu diễn bằng 2 bytes phía sau với giá trị $0x04A4 = 1188 \text{ bytes}$.
- **Value:** Dữ liệu thực của trường. Đối với `INTEGER`, DER sử dụng mã bù hai (two's complement). Do đó, nếu bit cao nhất của số nguyên dương là `1` (giá trị $\ge 0x80$), một byte `0x00` bắt buộc phải được chèn vào đầu để phân biệt với số âm (đó là lý do Modulus 2048-bit thường chiếm 257 bytes thay vì 256 bytes trong DER).

#### Bảng bóc tách cấu trúc ASN.1 DER thực tế từ file PEM khoá riêng tư (RFC 3447 PKCS#1 v2.2):
| Offset | Tag (Hex) | Loại thẻ | Độ dài (bytes) | Tên trường | Ý nghĩa cấu trúc |
| :---: | :---: | :---: | :---: | :--- | :--- |
| `0000` | `0x30` | `SEQUENCE` | `1188` | **RSAPrivateKey (SEQUENCE)** | Thẻ cha bọc toàn bộ 9 tham số toán học của khoá bí mật RSA. |
| `0004` | `0x02` | `INTEGER` | `1` | **version** | Phiên bản PKCS#1 (giá trị `0` cho khoá hai số nguyên tố). |
| `0007` | `0x02` | `INTEGER` | `257` | **modulus (n)** | Modulus công khai $n = p \times q$ (256 bytes kèm 1 byte `0x00` đệm dấu). |
| `0268` | `0x02` | `INTEGER` | `3` | **publicExponent (e)** | Số mũ công khai $e = 65537$ (`0x010001`). |
| `0273` | `0x02` | `INTEGER` | `256` | **privateExponent (d)** | Số mũ bí mật $d = e^{-1} \pmod{\phi(n)}$. |
| `0533` | `0x02` | `INTEGER` | `129` | **prime1 (p)** | Số nguyên tố bí mật thứ nhất $p$ (128 bytes + đệm `0x00`). |
| `0665` | `0x02` | `INTEGER` | `129` | **prime2 (q)** | Số nguyên tố bí mật thứ hai $q$ (128 bytes + đệm `0x00`). |
| `0797` | `0x02` | `INTEGER` | `129` | **exponent1 (dp)** | Số mũ rút gọn $d_p = d \bmod (p - 1)$ phục vụ định lý CRT. |
| `0929` | `0x02` | `INTEGER` | `129` | **exponent2 (dq)** | Số mũ rút gọn $d_q = d \bmod (q - 1)$ phục vụ định lý CRT. |
| `1061` | `0x02` | `INTEGER` | `128` | **coefficient (qInv)** | Nghịch đảo modulo $q_{\text{inv}} = q^{-1} \bmod p$. |

### 2.3. Ràng buộc kích thước dữ liệu $\le 190$ bytes (RSA-2048 OAEP-SHA256) và Mã hoá lai
- **Vì sao dữ liệu vào bị giới hạn $\le 190$ bytes?**
  - Đối với khoá RSA-2048, độ dài modulus $k = 2048 \text{ bits} = 256 \text{ bytes}$.
  - Chuẩn mã hoá an toàn hiện đại **OAEP** (Optimal Asymmetric Encryption Padding - RFC 3447) sử dụng hàm băm SHA-256 ($hLen = 32 \text{ bytes}$).
  - Cấu trúc đệm OAEP đòi hỏi:
    $$\text{MaxPlaintextLen} = k - 2 \cdot hLen - 2$$
  - Thay số vào công thức:
    $$\text{MaxPlaintextLen} = 256 - 2 \cdot 32 - 2 = 256 - 64 - 2 = 190 \text{ bytes}$$
  - Nếu dữ liệu đầu vào vượt quá $190 \text{ bytes}$, thuật toán RSA-OAEP-SHA256 sẽ báo lỗi vì không đủ chỗ chứa các trường tạo mặt nạ (`seed`, `lHash`, đệm).
- **Ứng dụng thực tế - Mô hình Mã hoá lai (Hybrid / Envelope Encryption):**
  - Trong thực tế, không bao giờ dùng RSA để mã hoá trực tiếp file hay tài liệu lớn vì chi phí tính toán luỹ thừa modulo cực kỳ nặng nề.
  - Thay vào đó, người ta áp dụng **Phong bì số (Digital Envelope)**:
    1. Sinh một khoá đối xứng ngẫu nhiên AES-256 ($32 \text{ bytes}$, hoàn toàn nhỏ hơn $190 \text{ bytes}$).
    2. Dùng AES-256 để mã hoá file lớn tốc độ cao (hàng trăm MB/s).
    3. Dùng RSA Public Key để mã hoá khoá AES-256 ($32 \text{ bytes} \rightarrow 256 \text{ bytes}$).
    4. Người nhận dùng RSA Private Key giải mã ra khoá AES-256, sau đó dùng khoá này giải mã file.

### 2.4. Đánh giá tốc độ thao tác Public Key vs Private Key và Nguyên nhân toán học
Kết quả đo đạc thực tế sau 500 lần lặp độc lập trên hệ thống:
- **Thao tác Public Key ($c = m^e \bmod n$):** `0,0287 ms/lần` ($34.880 \text{ ops/giây}$).
- **Thao tác Private Key ($m = c^d \bmod n$):** `0,8038 ms/lần` ($1.244 \text{ ops/giây}$).
- **Tỷ lệ chênh lệch:** Thao tác với Private Key chậm hơn Public Key **28,0 lần**.

#### Giải thích nguyên nhân toán học sâu sắc:
1. **Phép toán khoá công khai:**
   - Số mũ công khai là $e = 65537 = 2^{16} + 1 = \text{0x010001}$.
   - Dạng nhị phân của $e$ là `10000000000000001_2$ (gồm 17 bits, nhưng chỉ có đúng hai bit 1).
   - Thuật toán luỹ thừa nhanh *Bình phương và Nhân (Square-and-Multiply)* chỉ cần:
     - $16$ phép bình phương modulo.
     - Đúng $1$ phép nhân modulo.
     - Tổng cộng: **17 phép toán cơ bản**, do đó thời gian thực thi cực nhanh (chưa tới $0,03 \text{ ms}$).
2. **Phép toán khoá riêng tư:**
   - Số mũ bí mật $d$ là số nguyên ngẫu nhiên cực lớn có độ dài 2048 bits.
   - Trọng số Hamming trung bình của $d$ là $H(d) \approx 1024$ bits '1'.
   - Kể cả khi triển khai định lý số dư Trung Hoa (CRT) phân rã thành $c^{d_p} \bmod p$ và $c^{d_q} \bmod q$ với $p, q$ dài 1024-bit, mỗi nhánh vẫn cần khoảng $1024$ phép bình phương và $512$ phép nhân trên các số nguyên 1024-bit, sau đó kết hợp bằng $q_{\text{inv}}$.
   - Tổng khối lượng phép tính lớn hơn gấp hàng chục lần so với phép tính của khoá công khai.

---

## 3. BÀI 2 (Ý 8): HÀM BĂM SHA-256 & HIỆU ỨNG THÁC ĐỔ

### 3.1. Cấu trúc 64 vòng lặp của SHA-256
Hàm băm mật mã SHA-256 xử lý dữ liệu theo khối $512 \text{ bits}$ qua cấu trúc Merkle-Damgård với 64 vòng lặp biến đổi. Mỗi vòng sử dụng 8 thanh ghi trạng thái $32 \text{ bits}$ ($a, b, c, d, e, f, g, h$) kết hợp các hàm logic phi tuyến:
- $\text{Ch}(e, f, g) = (e \wedge f) \oplus (\neg e \wedge g)$ (Hàm lựa chọn)
- $\text{Maj}(a, b, c) = (a \wedge b) \oplus (a \wedge c) \oplus (b \wedge c)$ (Hàm số đông)
- $\Sigma_0(a) = \text{ROTR}^2(a) \oplus \text{ROTR}^{13}(a) \oplus \text{ROTR}^{22}(a)$
- $\Sigma_1(e) = \text{ROTR}^6(e) \oplus \text{ROTR}^{11}(e) \oplus \text{ROTR}^{25}(e)$
- Phép cộng modulo $2^{32}$ với các hằng số vòng $K_t$ (phần thập phân căn bậc ba của 64 số nguyên tố đầu tiên).

### 3.2. Tiêu chuẩn thác đổ nghiêm ngặt (Strict Avalanche Criterion - SAC)
- Tiêu chuẩn SAC yêu cầu: **Khi bất kỳ một bit đơn lẻ nào ở đầu vào bị thay đổi (lật từ 0 sang 1 hoặc ngược lại), thì mỗi bit ở đầu ra phải bị thay đổi với xác suất đúng $50\%$ ($P = 0.5$).**
- Điều này đảm bảo rằng kẻ tấn công không thể tìm ra bất kỳ quy luật toán học hay hàm tương quan nào giữa dữ liệu đầu vào và giá trị băm đầu ra (tính chất kháng tiền ảnh và kháng va chạm).

### 3.3. Số liệu thực nghiệm đo khoảng cách Hamming và tỷ lệ đảo bit
Hệ thống đã thực hiện thử nghiệm trên hai chuỗi văn bản chỉ khác nhau duy nhất 2 bit ở ký tự cuối:
- **Dữ liệu A:** `AnToanBaoMatThongTin_2026_Lab_A` (ASCII `'A'` = `01000001`)
- **Dữ liệu B:** `AnToanBaoMatThongTin_2026_Lab_B` (ASCII `'B'` = `01000010`)
- **Khác biệt đầu vào:** Đúng 1 ký tự, 2 bit khác nhau.
- **Mã băm SHA-256(A):** `1BBAA9013AC037EF9EAD0FDCEC4FC5787515C98A55005B105EB3F5E207397D1E`
- **Mã băm SHA-256(B):** `8294D38A49102894B8294E10D5F20DD5C25BD50DB35A075B1C6BABE24E2EC9F0`
- **Khoảng cách Hamming (Số bit bị đảo):** **$127 / 256 \text{ bits}$**
- **Tỷ lệ bit thay đổi:** **$49,61\%$** (gần như tiệm cận tuyệt đối mốc lý tưởng $50\%$).
- **Số ký tự Hex khác biệt:** $61 / 64 \text{ ký tự}$ thay đổi.
- **Đánh giá:** SHA-256 thoả mãn xuất sắc tiêu chuẩn thác đổ nghiêm ngặt SAC.

---

## 4. BÀI 2 (Ý 9): CHỮ KÝ SỐ RSA & CƠ CHẾ SINH CHỮ KÝ KHÁC NHAU

### 4.1. Chữ ký số định tính PKCS#1 v1.5 (Deterministic)
- Theo chuẩn cũ PKCS#1 v1.5, quá trình tạo chữ ký số gồm:
  $$\text{Signature} = (0x00 || 0x01 || PS || 0x00 || T)^d \bmod n$$
  Trong đó $T$ là cấu trúc ASN.1 chứa mã OID của SHA-256 và giá trị băm $H(M)$, $PS$ là chuỗi byte đệm cố định `0xFF`.
- **Hạn chế:** Vì không có yếu tố ngẫu nhiên, nếu ký $100$ lần trên cùng một văn bản bằng cùng một Private Key thì cả $100$ chữ ký số thu được hoàn toàn **giống hệt nhau từng bit**.
- Điều này có thể để lộ thông tin về tần suất ký và dễ bị tổn thương trước các kiểu tấn công vét cạn hoặc tấn công thích nghi bản rõ nếu kẻ tấn công biết trước cấu trúc bản đệm.

### 4.2. Phương pháp 1: Chuẩn mật mã học RSA-PSS (Probabilistic Signature Scheme - PKCS#1 v2.1)
- **Cơ chế hoạt động:**
  - RSA-PSS (RFC 3447 / PKCS#1 v2.1) là chuẩn chữ ký số xác suất hiện đại nhất hiện nay.
  - Trước khi thực hiện phép luỹ thừa khoá bí mật $d$, thuật toán tự động sinh một chuỗi muối ngẫu nhiên (**Random Salt** $s$, kích thước chuẩn bằng độ dài hàm băm: $32 \text{ bytes}$ đối với SHA-256).
  - Thuật toán băm thông điệp kết hợp với Salt: $H = \text{SHA256}(\text{Padding1} || mHash || s)$.
  - Sử dụng hàm sinh mặt nạ **MGF1** (Mask Generation Function 1 dựa trên SHA-256) để tạo mặt nạ làm mờ chuỗi Salt: $DB = \text{Padding2} || s$, sau đó $\text{maskedDB} = DB \oplus \text{MGF1}(H)$.
  - Khối mã hoá $EM = \text{maskedDB} || H || \text{0xBC}$ được luỹ thừa bí mật: $S = EM^d \bmod n$.
- **Ưu điểm vượt trội:**
  - Nhờ có $32 \text{ bytes}$ Salt ngẫu nhiên mới ở mỗi lần ký, chữ ký số đầu ra luôn **khác nhau $100\%$** ở mỗi lần thực hiện.
  - **Đặc biệt:** Người nhận khi xác thực bằng Public Key (`VerifyData` với `RSASignaturePadding.Pss`) chỉ cần tính $EM = S^e \bmod n$, lấy $H$ giải mặt nạ MGF1 để bóc tách Salt $s$, rồi kiểm tra lại đẳng thức băm. Người ký **không cần truyền riêng Salt** ra bên ngoài.
- **Kết quả thực nghiệm:**
  - Ký 3 lần liên tiếp trên cùng 1 văn bản bằng khoá riêng RSA-2048: Sinh ra 3 chuỗi chữ ký Base64 khác nhau hoàn toàn.
  - Người nhận xác thực cả 3 chữ ký bằng Public Key: Tất cả đều trả về `HỢP LỆ (VALID)`.

### 4.3. Phương pháp 2: Bổ sung Nonce & Timestamp ở tầng gói tin ứng dụng
- **Cơ chế hoạt động:**
  - Thay vì can thiệp ở tầng đệm mật mã học, ta thiết kế cấu trúc dữ liệu gói tin ở tầng ứng dụng (Application Level Payload):
    $$\text{Payload} = \text{Data} \ || \ \text{TimestampUtcTicks} \ || \ \text{Nonce}$$
  - Trong đó:
    - $\text{TimestampUtcTicks}$: Nhãn thời gian thực chuẩn UTC dạng ticks hoặc ISO 8601.
    - $\text{Nonce}$: Số ngẫu nhiên dùng một lần ($16 \text{ bytes} = 128 \text{ bits}$ sinh bằng CSPRNG).
  - Chữ ký số được tính trên toàn bộ Payload này:
    $$\text{Signature} = \text{Sign}(\text{SHA256}(\text{Data} \ || \ \text{Timestamp} \ || \ \text{Nonce}))$$
- **Ưu điểm bảo mật thực tế:**
  - Mỗi lần tạo giao dịch, Timestamp và Nonce luôn mới $\rightarrow$ Chữ ký luôn luôn khác nhau.
  - **Chống tấn công phát lại (Replay Attack):** Hệ thống phía nhận có thể kiểm tra xem Timestamp có nằm trong cửa sổ thời gian hợp lệ (ví dụ $\pm 5 \text{ phút}$) hay không, và lưu trữ danh sách Nonce đã xử lý vào bộ nhớ đệm (Redis / MemoryCache) để từ chối ngay lập tức bất kỳ gói tin nào bị gửi lại lần thứ hai.

---

## 5. KẾT LUẬN TỔNG THỂ

1. **Về Mã hoá đối xứng AES:**
   - AES-256 ở chế độ CBC kết hợp cơ chế Streaming Buffer 1MB cho tốc độ xử lý rất cao ($> 300 \text{ MB/s}$), hoàn toàn phù hợp cho các tập tin dung lượng lớn hàng Gigabyte mà không gây quá tải bộ nhớ RAM.
   - Thử nghiệm đối chiếu từng byte và mã băm SHA-256 khẳng định tính toàn vẹn tuyệt đối sau khi giải mã.
2. **Về Mã hoá bất đối xứng RSA:**
   - Cấu trúc ASN.1 DER trong file PEM thể hiện rõ tính chuẩn hoá quốc tế của các tham số toán học ($n, e, d, p, q, dp, dq, qInv$).
   - Ràng buộc kích thước đầu vào $\le 190 \text{ bytes}$ đối với RSA-2048 OAEP-SHA256 giải thích tại sao trong thực tế luôn sử dụng mô hình Mã hoá lai (Hybrid Encryption / Envelope Encryption).
   - Thao tác Public Key nhanh hơn Private Key khoảng 28 lần do sự khác biệt khổng lồ về trọng số nhị phân của số mũ công khai $e = 65537$ so với số mũ bí mật $d \approx 2048 \text{ bits}$.
3. **Về Hàm băm SHA-256 & Chữ ký số:**
   - Hàm băm SHA-256 thể hiện hiệu ứng thác đổ hoàn hảo với tỷ lệ đảo bit đạt $49,61\%$ khi đầu vào chỉ thay đổi nhẹ 2 bit, minh chứng tiêu chuẩn SAC được đảm bảo.
   - Hiện thực thành công 2 phương pháp tạo chữ ký khác nhau cho cùng một dữ liệu:
     + **RSA-PSS:** Chuẩn mật mã học ngẫu nhiên hoá bằng Salt và MGF1.
     + **Nonce & Timestamp:** Giải pháp cấp ứng dụng chống tấn công phát lại.
