# Phần 6: PE Base Relocations

**Giới thiệu**

Trong bài viết này, ta sẽ nói về PE base relocations. Ta sẽ biết nó là gì và xem qua relocation table.

---

## Relocation Table
Như mô tả của Microsoft documentation, base relocation table chứa các entries cho tất cả base relocation trong file image.

Ở trong section `.reloc`, relocation table được chia thành các block, mỗi block đại diện cho base relocations cho 1 page 4K và mỗi block phải bắt đầu trên 1 ranh giới 32-bit.

Mỗi block bắt đầu bằng 1 structure `IMAGE_BASE_RELOCATION` theo sau là số lượng các offset field entries.

Structure `IMAGE_BASE_RELOCATION` chỉ định RVA của trang và kích thước của block relocation.

```cpp=
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;
    DWORD   SizeOfBlock;
} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;
```
Mỗi offset của entry của trường là một WORD, 4 bit đầu tiên của nó xác định kiểu relocation (xem [Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) để biết danh sách các kiểu relocation), 12 bit cuối lưu ofset từ RVA được chỉ định trong structure `IMAGE_BASE_RELOCATION` ở đầu relocation block.

Mỗi relocation entry được xử lý bằng cách cộng thêm RVA của page vào địa chỉ của image base, sau đó bằng cách cộng offset được chỉ định trong relocation entry, có thể lấy được địa chỉ tuyệt đối của vị trí cần được sửa đổi.

File PE ta đang thấy chỉ có 1 relocation block, kích thước là `0x28` bytes:

![image](https://hackmd.io/_uploads/HkDmVzm66.png)

Ta biết rằng mỗi block bắt đầu bằng 1 structure dài 8 byte, có nghĩa là kích thước của các entries là `0x20` bytes (32 bytes), kích thước mỗi entry là 2 bytes nên tổng số entries là 16.

---

**Kết luận**

Đó là tất cả những gì tôi biết.
Cảm ơn mọi người đã đọc.
