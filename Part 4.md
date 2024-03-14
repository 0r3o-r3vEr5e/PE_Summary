# Phần 4: Data Directories, Section Headers và Sections

**Giới thiệu**

Trong bài trước, ta đã nói về NT headers và bỏ qua phần cuối cùng của Optional Header là data directories.

Trong bài viết này ta sẽ nói về data directory là gì và chúng được đặt ở đâu. Ta cũng sẽ đề cập đến section headers và các sections trong bài này.

---

## Data Directories
Trường thông tin cuối cùng của structure `IMAGE_OPTIONAL_HEADER` là một mảng các structure `IMAGE_DATA_DIRECTORY` được định nghĩa như sau:
```cpp=
IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
```
`IMAGE_NUMBEROF_DIRECTORY_ENTRIES` là một hằng số có giá trị là `16`, có nghĩa là mảng này có thể có lên tới 16 `IMAGE_DATA_DIRECTORY` entries:
```cpp=
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
```
Một structure `IMAGE_DATA_DIRECTORY` được định nghĩa như sau:
```cpp=
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```
Một structure đơn giản chỉ có 2 thành phần, thứ nhất là một RVA[^4] trỏ đến đầu của Data Directory và thứ hai là kích thước của Data Directory.

Vậy thì Data Directory là gì? Cơ bản một Data Directory là data được đặt bên trong một trong các sections của file PE.
Data Directories chứa thông tin hữu ích mà loader cần (ví dụ: một directory rất quan trọng là Import Directory chứa một danh sách các hàm bên ngoài được import vào từ các thư viện khác). Ta sẽ đề cập kĩ hơn về nó khi ta đi qua phần PE Imports.

**Lưu ý**: Không phải tất cả các Data Directory đều có chung 1 structure, `IMAGE_DATA_DIRECTORY.VirtualAddress` trỏ đến Data Directory, tuy nhiên loại của directory là cái xác định data chunk đó sẽ được parse ra như thế nào.

Dưới đây là danh sách các Data Directory được định nghĩa bởi `winnt.h`. (Mỗi một giá trị đại diện cho index của nó trong mảng DataDirectory):
```cpp=
// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
```
> Trên đây chỉ có 15 entries trong khi mảng này có 16 entries bởi vì entry còn lại là để dự trữ và phải được đặt là `0` nên ta sẽ không để cập đến ở đây.

Nếu ta nhìn nội dung của `IMAGE_OPTIONAL_HEADER.DataDirectory` của một file PE thực tế, ta có thể sẽ thấy một số entry mà cả 2 trường thông tin đều đặt là `0`:

![image](https://hackmd.io/_uploads/B1mm9Y3hp.png)

Điều này có nghĩa là Data Directory đó không được sử dụng (không tồn tại) trong file thực thi.

---

## Sections và Section Headers

**Sections**

Sections là nơi chứa data thực tế của file thực thi, chúng chiếm phần còn lại của file PE sau các headers, chính xác là sau section headers.
Một số sections có tên đặc biệt cho biết mục đích của chúng, ta sẽ đi qua một vài trong số chúng. Và một danh sách đầy đủ những cái tên này có thể tìm được trên [official Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) trong phần "Special Sections".
* **.text**: Chứa code thực thi của chương trình.
* **.data**: Chứa data được khởi tạo.
* **.bss**: Chứa data không được khởi tạo.
* **.radata**: Chứa data read-only được khởi tạo.
* **.edata**: Chứa export tables.
* **.idata**: Chứa import tables.
* **.reloc**: Chứa thông tin về relocation.
* **.rsrc**: Chứa tài nguyên được dùng bởi chương trình, bao gồm ảnh, icon hay thậm chí các mã nhị phân được nhúng.
* **.tls**: (Thread Local Storage), cung cấp bộ nhớ cho mọi luồng thực thi của chương trình

![image](https://hackmd.io/_uploads/Hk2M6F22a.png)

**Section Headers**

Sau Optional Header và trước các sections là các Section Headers. Các headers này chứa thông tin về các sections của file PE.

Một Section Header là một structure được đặt tên là `IMAGE_SECTION_HEADER` định nghĩa bởi `winnt.h` như sau:
```cpp=
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```
* **Name**: Trường thông tin đầu tiên của Section Header, một mảng dạng byte kích thước là `IMAGE_SIZEOF_SHORT_NAME` chứa tên của section. `IMAGE_SIZEOF_SHORT_NAME` có giá trị là `8` tức là section name không thể dài hơn 8 kí tự. Đối với các tên dài hơn, documentation đề cập đến cách giải quyết bằng cách điền vào trường thông tin này một offset trong string table, tuy nhiên các image thực thi không dùng string table nên giới hạn là 8 ký tự được giữ cho các image thực thi.
* **PhysicalAddress or VirtualSize**: là một `union` xác định nhiều tên cho cùng 1 thứ, trường thông tin này chứa tổng kích thước của section khi nó được load vào memory.
* **VirtualAddress**: Documentation nêu rõ rằng đối với các image thực thi, trường này chứa địa chỉ của byte đầu tiên so với image base khi được load vào memory và đối với object files thì nó chứa địa chỉ của byte đầu tiên của section trước khi relocation được áp dụng.
* **SizeOfRawData**: Trường này chứa kích thước của section trên ổ cứng, phải là bội số của `IMAGE_OPTIONAL_HEADER.FileAlignment`. `SizeOfRawData` và `VirtualSize` có thể khác nhau và lí do cho điều này ta sẽ nói sau trong bài viết này.
* **PointerToRawData**: Một con trỏ đến page đầu tiên của section bên trong file, đối với image thực thi thì nó phải là bội số của `IMAGE_OPTIONAL_HEADER.FileAlignment`.
* **PointerToRelocation**: Một con trỏ đến đầu các relocation entries cho section, được đặt giá trị là `0` đối với các file thực thi.
* **PointerToLineNumbers**: Một con trỏ đến đầu của các COFF[^5] line-number entries cho section, được đặt giá trị là `0` vì thông tin COFF debugging không được sử dụng nữa.
* **NumberOfRelocation**: Số lượng các relocation entries cho section, được đặt giá trị là `0` đối với image thực thi.
* **NumberOfLinenumbers**: Số lượng các COFF line-number entries cho section, được đặt là `0` vì thông tin COFF debugging không còn được sử dụng.
* **Characteristics**: Flags mô tả đặc điểm của section. Các đặc điểm này là thứ như nếu section này chứa code thực thi, chứa data được/không được khởi tạo, có thể chia sẽ trong memory. Một danh sách đầy đủ của flags này có thể tìm trên [official Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format).

`SizeOfRawData` và `VirtualSize` có thể khác nhau và điều này có thể xảy ra vì nhiều lí do khác nhau.

`SizeOfRawData` phải là bội số của `IMAGE_OPTIONAL_HEADER.FileAlignment`, nên nếu kích thước section nhỏ hơn giá trị đó thì phần còn lại sẽ được đệm và `SizeOfRawData` được làm tròn đến bội số nhỏ nhất của `IMAGE_OPTIONAL_HEADER.FileAlignment`.
Tuy nhiên khi section được load vào memory, nó không tuân theo sự căn chỉnh đó và chỉ chiếm phần kích thước thực tế.
Trong trường hợp này, `SizeOfRawData` sẽ lớn hơn `VirtualSize`.

Điều ngược lại cũng có thể xảy ra.
Nếu section chứa data không được khởi tạo thì các data này sẽ không được tính trên ổ cứng. Nhưng khi section được ánh xạ vào memory, section sẽ mở rộng để dành dung lượng bộ nhớ khi data không được khởi tạo được khởi tạo và sử dụng sau đó.
Điều này có nghĩa là section trên ổ cứng chiếm dụng ít hơn khi ở trong memory. Trong trường hợp này, `VirtualSize` sẽ lớn hơn `SizeOfRawData`.

Dưới đây là Section Headers trong PE-bear:

![image](https://hackmd.io/_uploads/B1vLeva2a.png)

Ta có thể thấy các trường `Raw Addr.` và `Virtual Addr.` lần lượt là `IMAGE_SECTION_HEADER.PointerToRawData` và `IMAGE_SECTION_HEADER.VirtualAddress`.

`Raw Size` và `Virtual Size` lần lượt là `IMAGE_SECTION_HEADER.SizeOfRawData` và `IMAGE_SECTION_HEADER.VirtualSize`.
Ta có thể hiểu cách 2 trường này được dùng để tính toán khi section kết thúc, trên cả ổ cứng và memory.
Ví dụ nếu ta lấy section `.text`, nó có Raw Address là `0x400` và Raw Size là `0x13400`, cộng lại ta được `0x13800` được hiển thị như là kết thúc của section trên ổ cứng.

Trường `Characteristics` đánh dấu một vài section là read-only, một số khác là read-write và một số là readable và executable.

`PointerToRelocations`, `NumberOfRelocations` và `NumberOfLinenumbers` được đặt là 0 như mong đợi.

---

**Kết luận**

Ta đã bàn luận về Data Directory là gì và về các section.
Phần sau sẽ là về PE Imports.
