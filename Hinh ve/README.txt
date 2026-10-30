SƠ ĐỒ CHO BÁO CÁO — "Nghiên cứu rootkit và cách phòng chống"
=============================================================

Trong file .docx có 5 chỗ giữ hình, dạng:

    [Hình 2.1. — chỗ dành cho sơ đồ: ...]

Bạn có thể:
  (a) chèn trực tiếp file PNG trong thư mục này vào đúng vị trí, rồi xoá dòng placeholder; hoặc
  (b) tự vẽ lại theo mô tả bên dưới nếu muốn hình khác đi.

Ánh xạ placeholder -> file:

  Hình 2.1  ->  fig_2_1.png   Kiến trúc tổng thể của LongsDriver (user mode -> IOCTL ->
                              các module -> cấu trúc hạt nhân bị tác động)
  Hình 3.1  ->  fig_3_1.png   Danh sách tiến trình trước/sau khi DKOM unlink
                              (EPROCESS B bị gỡ, Flink = Blink = chính nó)
  Hình 4.1  ->  fig_4_1.png   Quy trình vá cổng ObRegisterCallbacks
                              (kiểm tra PatchGuard -> kiểm tra chữ ký byte -> ghi -> revert)
  Hình 5.1  ->  fig_5_1.png   Chuỗi truy cập ETW-TI: slot REGHANDLE -> ETW_REGISTRY_ENTRY
                              -> EnableInfo -> IsEnabled -> InterlockedExchange
  Hình 5.2  ->  fig_5_2.png   Quy trình vô hiệu hoá PatchGuard (pattern scan -> kiểm tra
                              đủ chữ ký -> vô hiệu routine kiểm tra -> đặt cờ)

Gợi ý kích thước khi chèn (giữ đúng tỉ lệ, khổ A4, lề 2 cm):
  Hình 2.1: rộng ~16 cm    Hình 3.1: rộng ~15 cm
  Hình 4.1: cao ~16 cm     Hình 5.1: rộng ~16 cm
  Hình 5.2: cao ~15 cm

Sau khi chèn hình, bấm Ctrl+A rồi F9 (chọn "Update entire table") để Word tính lại
số trang trong Mục lục.

BẢNG
====
Báo cáo không còn bảng dựng sẵn (bảng do công cụ sinh ra thiếu <w:tblGrid> nên Word
báo lỗi khi mở). Tại mỗi vị trí bảng có một khối như sau:

    [Bảng 2.1 — Nhóm chức năng và mã IOCTL của LongsDriver — chỗ dành vẽ bảng]
    Nhóm chức năng  |  Mã IOCTL  |  Mô-đun hiện thực
    Kiểm tra trạng thái  |  IOCTL_PING (0x800), ...  |  Dispatch.c, Bypass.c
    ...

Cách dựng lại bảng: bôi đen các dòng dữ liệu (không gồm dòng [Bảng ...]),
Insert > Table > Convert Text to Table..., chọn "Other" và gõ dấu |.

Danh sách 8 bảng trong báo cáo:
  Bảng 2.1  Nhóm chức năng và mã IOCTL           (5 dòng dữ liệu)
  Bảng 2.2  Offset EPROCESS/ETHREAD              (7 dòng)
  Bảng 2.3  Cơ chế bảo vệ của Windows            (5 dòng)
  Bảng 3.1  Nguồn sự thật bị/không bị DKOM       (7 dòng)
  Bảng 4.1  Quyền bị cắt khỏi handle             (8 dòng)
  Bảng 6.1  Cấu hình môi trường thực nghiệm      (12 dòng)
  Bảng 6.2  Kịch bản kiểm thử                    (8 dòng)
  Bảng 7.1  Kỹ thuật <-> dấu hiệu phát hiện      (8 dòng)

