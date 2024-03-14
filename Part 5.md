# Phần 5: PE Imports (Import Directory Table, ILT[^1], IAT[^2])

**Giới thiệu**

Bài viết này tìm hiểu về một khía cạnh rất quan trọng của file PE - PE imports. Để hiều PE file xử lý các thông tin import như thế nào, ta sẽ đi qua một số Data Directories đại diện cho section Import Data (`.idata`), Import Directory Table, ILT hay cũng gọi là INT[^8] và IAT.

## Import Directory Table
Import Directory Table là một Data Directory đặt ở đầu section `.idata`.
Nó bao gồm một mảng các structure `IMAGE_IMPORT_DESCRIPTOR`, mỗi một structure dành cho một DLL. Nó không có một kích thước cố định, nên structure `IMAGE_IMPORT_DESCRIPTOR` cuối cùng của mảng được zeroed-out (NULL-Padded) để cho biết kết thúc của Import Directory Table.

`IMAGE_IMPORT_DESCRIPTOR` được định nghĩa như dưới đây:
```cpp=
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;
        DWORD   OriginalFirstThunk;
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;
    DWORD   ForwarderChain;
    DWORD   Name;
    DWORD   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;
```
* **OriginalFirstThunk**: RVA của ILT
* **TimeDateStamp**: Mốc ngày giờ, ban đầu được đặt là `0` nếu không bị ràng buộc và `-1` nếu bị ràng buộc. Trong trường hợp một import không liên kết, dấu ngày giờ sẽ được cập nhật thành dấu của DLL sau khi image được liên kết. Trong trường hợp một import ràng buộc, nó vẫn được đặt là `-1` và dấu thời gian thực của DLL có thể tìm thấy trong BOUND Import Directory Table trong `IMAGE_BOUND_IMPORT_DESCRIPTOR` tương ứng. Ta sẽ đề cập đến các import ràng buộc trong phần tiếp theo của bài viết.
* **ForwarderChain**: Index của tham chiếu forwarder chain đầu tiên. Đây là thứ có vai trò trong DLL forwarding. (DLL forwarding là khi một DLL chuyển tiếp một số hàm được export đến một DLL khác)
* **Name**: Một RVA của một chuỗi ASCII chứa tên của các DLL được import.
* **FirstThunk**: RVA của IAT.

---

## Bound Imports
Về cơ bản, một bound imports nghĩa là import table chứa các địa chỉ cố định cho các hàm được import. Các địa chỉ này được linker tính toán và ghi trong compile time.

Việc sử dụng bound imports là một phương án tối ưu tốc độ, nó giảm thời gian mà loader cần để phân giải địa chỉ các hàm và điền vào IAT. Tuy nhiên, nếu như tại run-time mà các bound address không khớp với bound address thật sự thì loader sẽ phân giải các địa chỉ này một lần nữa và sửa IAT.

Khi nói về `IMAGE_IMPORT_DESCRIPTOR.TimeDateStamp`, tôi đã đề cập đến trường hợp import ràng buộc, dấu ngày giờ sẽ đặt là `-1` và dấu thời gian thực của DLL có thể tìm thấy trong `IMAGE_BOUND_IMPORT_DESCRIPTOR` tương ứng trong Bound Import Data Directory.

**Bound Import Data Directory**

Bound Import Data Directory giống với Import Directory Table. Tuy nhiên như tên gọi, nó chứa thông tin của các bound import.

Nó bao gồm một mảng các structure `IMAGE_BOUND_IMPORT_DESCRIPTOR` và kết thực bằng một `IMAGE_BOUND_IMPORT_DESCRIPTOR` được zeroed-out.

`IMAGE_BOUND_IMPORT_DESCRIPTOR` được định nghĩa như sau:
```cpp=
typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
    DWORD   TimeDateStamp;
    WORD    OffsetModuleName;
    WORD    NumberOfModuleForwarderRefs;
// Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
} IMAGE_BOUND_IMPORT_DESCRIPTOR,  *PIMAGE_BOUND_IMPORT_DESCRIPTOR;
```
* **TimeDateStamp**: Dấu ngày giờ của DLL được import.
* **OffsetModuleName**: Một offset đến chuỗi có tên của DLL được import. Nó là offset từ `IMAGE_BOUND_IMPORT_DESCRIPTOR` đầu tiên
* **NumberOfModuleForwarderRefs**: Số lượng các structure `IMAGE_BOUND_FORWARDER_REF` ngay sau structure này. `IMAGE_BOUND_FORWARDER_REF` là một structure mà giống như `IMAGE_BOUND_IMPORT_DESCRIPTOR`, sự khác biệt duy nhất là trường thông tin cuối được lưu trữ.

Đó là tất cả những gì ta cần biết về bound imports.

---

## Import Lookup Table (ILT)
Đôi khi, mọi người gọi là Import Name Table.

Mọi DLL được import đều có một Import Lookup Table.
`IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk` chứa RVA đến ILT của DLL tương ứng. 

ILT về cơ bản là một bảng chứa các tên hoặc tham chiếu, nó cho loader biết các hàm nào cần từ DLL được import.

ILT bao gồm một mảng chứa các số 32-bit (đối với PE32) hoặc 64-bit đối với (PE32+), số cuối cùng được zeroed-out để thể hiện kết thúc của ILT.

Một entry của các entries này encode thông tin như sau:
* **Bit 31/63 (most significant bit)**: nó được gọi là Ordinal/Name flag, nó cho biết liệu rằng import hàm đó bằng tên hoặc bằng ordinal.
* **Bits 15-0**: nếu Ordinal/Name flag được đặt là `1`, các bits này được dùng để chứa ordinal number 16-bit mà sẽ được sử dụng để import hàm, các bit 30-15/62-15 đối với PE32/PPE32+ phải được đặt là `0`.
* **Bits 30-0**: Nếu Ordinal/Name flag được đặt là `0` thì các bit này được dùng để chứa RVA của Hint/Name table.

**Hint/Name Table**

Hint/Name Table là một structure được định nghĩa trong `winnt.h` là `IMAGE_IMPORT_BY_NAME`:
```cpp=
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```
* **Hint**: Một WORD chứa một số, số này được dùng để tìm hàm. Số đầu trước tiên được dùng như một index của export name pointer table, nếu thất bại thì thực hiện binary search trên export name pointer table của DLL.
* **Name**: Một chuỗi null-terminated chứa tên của hàm import.

---

## Import Address Table (IAT)
Trên ổ cứng, IAT giống như ILT, tuy nhiên trong quá trình bounding khi binary đang được load vào memory, các entries của IAT bị ghi đè bằng các địa chỉ của các hàm mà được import.

## Summary
Tổng kết lại những gì đã đề cập trong bài viết, đối với mỗi DLL mà file thực thi đang load hàm từ đấy, sẽ có một `IMAGE_IMPORT_DESCRIPTOR` bên trong Image Directory Table.
`IMAGE_IMPORT_DESCRIPTOR` sẽ chứa tên của DLL và 2 trường thông tin chứa các RVA của ILT và IAT.
ILT sẽ chứa các tham chiếu cho tất cả các hàm mà được import từ DLL.
IAT giống như ILT cho đến khi file thực thi được load vào memory, sau đó loader sẽ điền IAT bằng địa chỉ thực tế của các hàm được import.
Nếu DLL import là một bound import, thì thông tin import sẽ được chứa trong các structure `IMAGE_BOUND_IMPORT_DESCRIPTOR` trong một Data Directory riêng biệt gọi là Bound Import Data Directory.

Dưới đây là Import Directory Table của file thực thi:

![image](https://hackmd.io/_uploads/HkcZaia3T.png)

Tất cả các entries này đều là các `IMAGE_IMPORT_DESCRIPTOR`.

Như ta thấy, `TimeDateStamp` của tất cả các import được đặt là `0`, có nghĩa là không có import nào trong số chúng là bound import. Điều này cũng được xác nhận trong cột `Bound?` được thêm bởi PE-bear.

Ví dụ, nếu ta lấy `SHELL32.dll` và theo RVA của ILT của nó (tham chiếu bởi `OriginalFirstThunk`), chúng ta sẽ tìm thấy chỉ có 1 entry (vì chỉ có 1 hàm được import), và entry đó trông như thế này.

![image](https://hackmd.io/_uploads/H1sRE26np.png)

Đây là file thực thi 32-bit nên entry có độ dài 32 bit. 
Như ta thấy, byte cuối cùng đặt là `0`, thể hiện rằng một Hint/Table name nên được dùng để tìm kiếm hàm.
Ta biết RVA của Hint/Table name này nên được tham chiếu bởi 3 bytes đầu, nên ta cần theo RVA `0x16AFC`:

![image](https://hackmd.io/_uploads/BkrsThTnT.png)

![image](https://hackmd.io/_uploads/BJYCRhp2a.png)

Bây giờ ta thấy một structure `IMAGE_IMPORT_BY_NAME`, 2 bytes đầu chưa hint ở trong trường hợp này là `0x1B0`. Phần còn lại của structure chứa tên đầy đủ của hàm là `ShellExecuteW`.
Ta có thể xác nhận rằng cách giải thích của chúng ta về data là đúng bằng cách nhìn cách PE-bear parse nó rồi ta sẽ thấy kết quả tương tự:

![image](https://hackmd.io/_uploads/BkTRy6a36.png)

---

**Kết Luận**
Đó là tất cả những gì cần nói về PE imports, trong phần tiếp tôi sẽ đề cập đến PE base relocation.

[^1]: Import Lookup Table
[^2]: Import Address Table
