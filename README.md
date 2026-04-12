# PBL4: Cross-Platform Secure VPN System

Hệ thống Mạng Riêng Ảo (VPN) bảo mật được phát triển bằng **C/C++**, hỗ trợ đa nền tảng với Server chạy trên Linux và Client hỗ trợ cả **Linux** lẫn **Windows**. Đây là sản phẩm của Đồ án Lập trình mạng (PBL4), tập trung vào kiến trúc định tuyến, tương tác card mạng ảo (TUN/TAP) và mã hóa gói tin chuyên sâu.

## Điểm nổi bật của dự án

* **Đa nền tảng (Cross-Platform):** Hệ thống được thiết kế linh hoạt với các nhánh riêng biệt xử lý API mạng đặc thù của từng hệ điều hành (POSIX Sockets cho Linux và Winsock2 cho Windows).
* **Bảo mật mức cao (TLS & AES-256-GCM):** Tích hợp quy trình bắt tay TLS và thuật toán mã hóa AES-256-GCM. Đảm bảo dữ liệu luôn được mã hóa an toàn, chống lại các cuộc tấn công nghe lén (Packet Sniffing).
* **Virtual Network Interface:** Tương tác trực tiếp với virtual network interface (`TUN/TAP` trên Linux và `TAP-Windows` trên Windows) để đánh chặn và định tuyến lại các gói tin IP.

## Cấu trúc Repository (Các Branch chính)

Dự án được chia thành 3 nhánh (branch) chính tương ứng với 3 thành phần của hệ thống:
* **`master`**: Chứa mã nguồn của **VPN Server** (Chạy trên môi trường Linux/Ubuntu).
* **`masterClient`**: Chứa mã nguồn của **VPN Client cho MacOS**.
* **`winClient`**: Chứa mã nguồn của **VPN Client cho Windows**.

## Công nghệ sử dụng

* **Ngôn ngữ:** `C/C++`
* **Lập trình mạng:** `POSIX Sockets` (Linux), `Winsock2` (Windows)
* **Card mạng ảo:** Giao thức `TUN/TAP` (Linux), `TAP-Windows Adapter` (Windows)
* **Mã hóa & Bảo mật:** `OpenSSL` (TLS, AES-256-GCM)

## Hướng dẫn cài đặt & Khởi chạy

### 1. Triển khai VPN Server (Ubuntu/Linux)
Server cần được chạy trên môi trường Linux có quyền `root`.
```bash
git clone [https://github.com/juffww/PBL4---Build-a-VPN-system.git](https://github.com/juffww/PBL4---Build-a-VPN-system.git)
cd PBL4---Build-a-VPN-system
git checkout master

# Build và chạy Server
make
sudo ./vpn-server --port 8080
```

### 2. Triển khai VPN Client trên MacOS
Mở một Terminal khác hoặc máy Linux khác:
```bash
git clone [https://github.com/juffww/PBL4---Build-a-VPN-system.git](https://github.com/juffww/PBL4---Build-a-VPN-system.git)
cd PBL4---Build-a-VPN-system
git checkout masterClient

# Build và chạy Client
make
sudo ./vpn-client --server-ip [IP_CUA_SERVER] --port 8080
```
*Cấu hình định tuyến (Routing Table):*
```bash
sudo ip route add [TARGET_IP] dev tun0
```

### 3. Triển khai VPN Client trên Windows
* **Yêu cầu:** Máy tính cần cài đặt driver [TAP-Windows](https://build.openvpn.net/downloads/releases/) để tạo card mạng ảo.
* **Biên dịch:** Sử dụng MinGW hoặc Visual Studio C++.

```bash
git clone [https://github.com/juffww/PBL4---Build-a-VPN-system.git](https://github.com/juffww/PBL4---Build-a-VPN-system.git)
cd PBL4---Build-a-VPN-system
git checkout winClient

# Thực hiện build bằng trình biên dịch C++ trên Windows của bạn (vd: make / msbuild)
# Chạy executable dưới quyền Administrator
vpn-client.exe --server-ip [IP_CUA_SERVER] --port 8080
```

## Thách thức & Kỹ năng đạt được
* Xử lý sự khác biệt về API Lập trình mạng giữa Linux (POSIX) và Windows (Winsock2).
* Nắm vững cấu trúc của các Header (IPv4, TCP, UDP) và cách xử lý phân mảnh gói tin qua MTU.
* Quản lý quy trình mã hóa luồng dữ liệu thời gian thực (AES-GCM) mà không làm tăng quá nhiều độ trễ (latency) của mạng.
