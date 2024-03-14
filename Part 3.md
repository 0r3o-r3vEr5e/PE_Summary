# Phần 3: NT Headers

**Giới thiệu**

Trong phần trước, ta đã tìm hiểu về cấu trúc của DOS Header và dịch ngược DOS stub

Trong phần này, ta sẽ tìm hiều về phần NT Headers của cấu trúc file PE

Trước khi vào phần này, ta cần biết về một chủ đề quan trọng mà chúng ta sẽ gặp rất nhiều sắp tới là Relative Virtual Address (hay RVA). Một RVA là một offset từ vị trí image được load vào memory (Image Base). Vậy nên để dịch RVA sang absolute virtual address, bạn cần cộng thêm giá trị của RVA vào giá trị của Image Base. Sau này ta sẽ thấy rằng file PE phụ thuộc rất nhiều vào RVA.

---

## NT Headers (IMAGE_NT_HEADERS)
NT headers là một structure trong thư viện `winnt.h` là `IMAGE_NT_HEADERS`, dựa vào định nghĩa của nó ta thấy rằng nó có 3 thành phần: Signature dạng `DWORD`, structure `IMAGE_FILE_HEADER` được gọi là `FileHeader` và structure `IMAGE_OPTIONAL_HEADER` gọi là `OptionalHeader`.
Structure này có 2 phiên bản khác nhau: một là cho file thực thi 32-bit (còn gọi là `PE32`) đặt tên là `IMAGE_NT_HEADERS` và một cho file thực thi 64-bit (còn gọi là `PE32+`) đặt tên là `IMAGE_NT_HEADERS64`.
Sự khác nhau chính giữa 2 phiên bản này là do structure `IMAGE_OPTIONAL_HEADER` có 2 phiên bản: `IMAGE_OPTIONAL_HEADER32` cho `PE32` và `IMAGE_OPTIONAL_HEADER64` cho `PE32+`.

```Cpp=
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```

### Signature
Trường thông tin đầu tiên của NT headers là PE signature kiểu dữ liệu `DWORD` nên signature này chiếm 4 bytes
Giá trị luôn là `0x50450000` hay `PE\0\0` trong ASCII.

Ta có thể thấy rõ điều này trong PE-bear:

![image](https://hackmd.io/_uploads/rJjrMTcnT.png)

### File Header (IMAGE_FILE_HEADER)
Còn được gọi là "The COFF File Header", File Header là một structure giữ một số thông tin về file PE.
Định nghĩa: `IMAGE_FILE_HEADER` trong `winnt.h` như dưới đây
```cpp=
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```
Structure này có 7 thành phần:
* **Machine**: đây là số biểu thị kiểu máy (CPU Architecture) mà file thực thi nhắm đến. Trường thông tin này có nhiều giá trị thực tế nhưng ta chỉ quan tâm 2 giá trị: `0x8864` cho `AMD64` và `0x14c` cho `i386`. Danh sách các giá trị cụ thể có thể tìm ở [official Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format).
* **NumberOfSections**: Trường thông tin này giữ số lượng sections (hoặc là số lượng section headers aka kích thước của section table).
* TimeDateStamp: Một `unix` timestamp thể hiện file được tạo khi nào
* PointerToSymbolTable và NumberOfSymbols: 2 trường thông tin này giữ offset của file chỉ đến COFF symbol table và số lượng entry trong symbol table đó. Tuy nhiên chúng được đặt giá trị là `0` có nghĩa là không có COFF symbol table. Điều này được thực hiện là do thông tin COFF debugging không được dùng nữa.
* SizeOfOptionalHeader: kích thước của Optional Header.
* Characteristics: là một flag thể hiện thuộc tính của file. Các thuộc tính này có thể là những thứ như file thực thi được, file hệ thông và không phải chương trình của người dùng và nhiều hơn nữa. Danh sách đầy đủ có thể tìm tại [official Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format).

Dưới đây là ví dụ nội dung File Header của file PE thực tế:

![image](https://hackmd.io/_uploads/ByMjo6cnT.png)

> Trong một số trường hợp, trường thông tin `TimeDateStamp` được thay thế bằng trường thông tin `ReproChecksum` như hình dưới. Điều này là do một số file PE được build với `/Brepro` flag. Flag này cho phép reprocible builds. Điều này có nghĩa là các bản build này phải chung code, chung settings và chung hash. Các phiên bản build này nếu như lưu trường `TimeDateStamp` thì sẽ không có chung hash nên thay vào đó nó sẽ lưu một cái checksum.
>
> ![image](https://hackmd.io/_uploads/SJRL2p53p.png)

### Optional Header (IMAGE_OPTIONAL_HEADER)
Optional Header là header quan trọng nhất của NT headers, PE loader tìm thông tin cụ thể được cung cấp bởi header này để có thể load và chạy file thực thi.
Nó được gọi là Optional Header vì một số file như object file không cần đến, nhưng header này cần thiết với các file image.
Nó không có một kích thước cố định, đó là lí do tại sao trường thông tin `IMAGE_FILE_HEADER.SizeOfOptionalHeader` tồn tại.

Tám trường thông tin đầu tiên của Optional Header structure là tiêu chuẩn cho mọi implementation của COFF file format, phần còn lại là một phần mở rộng của COFF optional header tiêu chuẩn được định nghĩa bởi Microsoft, Windows PE loader và linker cần các trường thông tin thêm này của structure.

Như đã đề cập trước đó, có 2 phiên bản Optional Header: một cho file thực thi 32-bit và một cho file thực thi 64-bit.
Sự khác nhau giữa 2 phiên bản này nằm ở 2 yếu tố:
* **Kích thước của structure (hay số lượng các trường thông tin ở trong structure)**: `IMAGE_OPTIONAL_HEADER32` có 31 trường thông tin trong khi `IMAGE_OPTIONAL_HEADER64` chỉ có 30 trường thông tin. Trường thông tin thêm ở bản 32-bit là một DWORD tên là `BaseOfData` giữ RVA phần bắt đầu của data section.
* **Kiểu dữ liệu của một số trường thông tin**: 5 trường thông tin dưới đây của Optional Header được định nghĩa là `DWORD` trong bản 32-bit và `ULONGLONG` trong bản 64-bit:
  * **ImageBase**
  * **SizeOfStackReserve**
  * **SizeOfStackCommit**
  * **SizeOfHeapReserve**
  * **SizeOfHeapCommit**

Dưới đây là structure của 2 phiên bản Optional Header:
```cpp=
typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //

    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    //
    // NT additional fields.
    //

    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```
```cpp=
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
```
* **Magic**: Tài liệu Microsoft mô tả trường thông tin này là một số nguyên định danh trạng thái của image, có 3 giá trị phổ biến:
  * **0x10B**: định danh image là file thực thi `PE32`
  * **0x20B**: định danh image là file thực thi `PE32+`
  * **0x107**: định danh image là image ROM[^1] 
  Giá trị của trường thông tin này là cái để xác định file thực thi là 32-bit hay 64-bit, Windows PE loader bỏ qua trường thông tin`IMAGE_FILE_HEADER.Machine`.
* **MajorLinkerVersion** và **MinorLinkerVersion**: Linker đến số phiên bản major và minor
* **SizeOfCode**: Trường thông tin này giữ kích thước của code section (`.text`), hay tổng số của tất cả code sections nếu như có nhiều sections.
* **SizeOfInitializedData**: Trường thông tin này giữ kích thước của section data được khởi tạo (`.data`) hoặc tổng số các sections tương tự.
* **SizeOfUninitializedData**: Trường thông tin này giữ kích thước của section dữ liệu không được khởi tạo (`.bss`) hoặc tổng số các sections tương tự.
* **AddressOfEntryPoint**: địa chỉ RVA của entry point khi file được load vào memory. Documentation nêu rõ rằng đối với program images, địa chỉ tương đối này trỏ đến địa chỉ bắt đầu và với drivers thiết bị nó trỏ đến hàn khởi tạo. Đối với DLLs thì entry point là một thông tin optional và trong trường hợp không có entry point thì trường `AddressOfEntryPoint` được đặt là `0`. 
* **BaseOfCode**: một địa chỉ RVA của phần bắt đầu của code section khi file được load vào memory.
* **BaseOfData (PE32 Only)**: một địa chỉ RVA của phần bắt đầu của data section khi file được load vào memory.
* **ImageBase**: Trường thông tin này chứa địa chỉ ưu tiên của byte đầu tiền của image khi được load vào memory, giá trị này phải là bội số của 64K. Vì các biện pháp bảo vệ memory như ASLR và rất nhiều lý do khác, địa chỉ được chỉ định bởi trường thông tin này không được sử dụng. Trong trường hợp này, PE loader chọn một khoảng memory chưa được sử dụng để load image vào, sau khi load vào địa chỉ đó, loader sẽ thực hiện một process gọi là relocating - sửa các constant address[^2] ở trong image để hoạt động với image base mới. Có một section chứa thông tin về các vị trí sẽ cần phải sửa nếu như cần relocation, section này là relocation section (`.reloc`), ta sẽ tìm hiểu thêm trong bài viết sau. 
* **SectionAlignment**: Trường này chứa giá trị được dùng để căn chỉnh section ở trong memory (tính bằng bytes), các section được căn chỉnh trong ranh giới bộ nhớ là bội số của giá trị này. Documentation nêu rõ rằng giá trị mặc định này là kích thước của page cho kiến trúc và nó không thể nhỏ hơn giá trị của `FileAlignment`.
* **FileAlignment**: Tương tự với `SectionAlignment`, trường này chứa giá trị mà được sử dụng việc căn chỉnh data raw **trên ổ cứng** (tính bằng bytes). Nếu kích thước của data thực tế trong một section nhỏ hơn giá trị `FileAlignment`, phần còn lại của chunk sẽ được đệm bằng `00` để giữ ranh giới căn chỉnh. Documentation nêu rõ rằng giá trị này nên là lũy thừa ủa 2 trong khoảng từ 512 đến 64KB và nếu giá trị của `SectionAlignment` nhỏ hơn kích thước page của kiến trúc thì kích thước của `FileAlignment` và `SectionAlignment` phải khớp nhau.
* **MajorOperatingSystemVersion, MinorOperatingSystemVersion, MajorImageVersion, MinorImageVersion, MajorSubsystemVersion và MinorSubsystemVersion**: Những trường thông tin này của structure theo thứ tự chỉ định số phiên bản chính của hệ điều hành được yêu cầu, số phiên bản phụ của hệ điều hành được yêu cầu, số phiên bản chính của file image, số phiên bản phụ của file image, số phiên bản chính của subsystem và số phiên bản phụ của subsystem.
* **Win32VersionValue**: Một trường thông tin dự trữ mà theo documentation trường này nên được đặt là `0`.
* **SizeOfImage**: kích thước của file image (tính bằng bytes), bao gồm tất cả các header. Nó được làm tròn là bội số của `SectionAlignment` bởi vì giá trị này được dùng khi load image vào memory.
* **SizeOfHeaders**: kích thước của DOS stub, PE header (NT Headers) và các section headers được làm tròn là bội số của `FileAlignment`.
* **CheckSunm**: Một giá trị checksum của file image, được dùng để validate trong thời gian load.
* **Subsystem**: Trường này chỉ định Windows subsystem (nếu có) mà cần để chạy file image. Một danh sách hoàn chỉnh về các giá trị khả dĩ của trường này có thể tìm thấy tại [official Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format).
* **SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve and SizeOfHeapCommit**: Các trường này theo thứ tự chỉ định kích thước của stack để dự trữ, kích thước stack để commit, kích thước của không gian heap cục bộ để dự trữ, kích thước không gian heap cục bộ để commit.
* **LoaderFlags**: trường thông tin dự trữ mà documentation đề cập rằng nên được đặt là `0`.
* **NumberOfRvaAndSizes**: kích thước của mảng `DataDirectory`.
* **DataDirectory**: một mảng của structure `IMAGE_DATA_DIRECTORY`. Chúng ta sẽ tìm hiểu thêm trong bài viết sau.

Dưới đây là nội dung của Optional Header của một file PE thực tế:

![image](https://hackmd.io/_uploads/BkYE8uh36.png)

Ta có thể nói qua về một số trường thông tin này, đầu tiền là trường `Magic` ở đầu header, nó có giá trị là `0x10B` có nghĩa đây là file thực thi `PE32`.

Ta có thể thấy được entry point RVA là `0x11EC0` và RVA bắt đầu code section là `0x1000` tuân theo sự căn chỉnh được định nghĩa bởi trường `SectionAlignment` có giá trị là `0x1000`.

File alignment được đặt giá trị là `0x200` và ta có thể xác thực điều này bằng cách nhìn vào bất kỳ section nào (ví dụ: data section):

![image](https://hackmd.io/_uploads/r13fF_32p.png)

Như ta thấy, nội dung thực tế của data section chỉ từ `0x13800` đến `0x139F4` tuy nhiên phần còn lại của section được đệm đến `0x139FF` để tuân thủ căn chỉnh được xác định bởi `FileAlignment`.

`SizeOfImage` được đặt giá trị là `1B000` và `SizeOfHeader` được đặt giá trị là `400`, cả 2 lần lượt là bội số của `SectionAlignment` và `FileAlignment`.

Thực chất nội dung của optional header còn có `DataDirectory` nhưng mà ta vẫn chưa đề cập đến nó.

---

**Kết Luận**

Tổng kết lại, chúng ta đã tìm hiểu về cấu trúc của NT Headers và tìm hiểu chi tiết về cấu trúc của File Header và Optional Header.
Bài viết tới sẽ nói về Data Directories, Section Headers và các section.

[^1]: Read Only Memory
[^2]: Địa chỉ cố định