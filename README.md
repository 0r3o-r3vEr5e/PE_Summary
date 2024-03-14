# PE_Summary

Đây là bản dịch của [blog của 0xRick](https://0xrick.github.io/win-internals/pe2/)
This is a Vietnamese translation of [0xRick's Blog](https://0xrick.github.io/win-internals/pe2/)
# Phần 1: Tổng quan

**Giới thiệu**

Mục tiêu của post này là giới thiệu cơ bản về cấu trúc file PE một cách tổng quan nhất

---

## PE files
Viết tắt của Portable Executable, PE file là một định dạng cho các file thực thi chạy trên Windows OS dựa trên định dạng COFF (Common Object File Format)

Ngoài .exe, Dynamic Link Library (.dll), Kernel modules (.srv), Control Panel apps (.cpl)... cũng là PE files.

Một file PE là cấu trúc dữ liệu có chứa các thông tin cần thiết để OS loader có thể load file thực thi vào Memory và thực thi nó

## Cấu trúc tổng quan
Một file PE tiêu biểu sẽ tuân theo cấu trúc như hình dưới

![image](https://hackmd.io/_uploads/ryi-Nqtna.png)

Nếu ta mở một file thực thi bằng `PE-bear`, ta cũng sẽ thấy được điều tương tự:

![image](https://hackmd.io/_uploads/BJUWScY2a.png)

**DOS Header**
Mỗi file PE đều bắt đầu bằng 1 structure dài 64 bytes được gọi là DOS header với vai trò làm cho PE file là file thực thi MS-DOS

## DOS Stub
Sau DOS Header là DOS Stub có chức năng in ra dòng lỗi "This program cannot be run in DOS mode" khi chương trình được khởi chạy trong DOS mode

## NT Headers
NT Header bao gồm 3 phần chính:
* PE Signature: là 4-byte signature định danh file là PE file
* File Header: một `COFF` File Header tiêu chuẩn chứa một số thông tin về file PE
* Optional Header: là phần header quan trọng nhất của NT Headers cung cấp thông tin quan trọng cho OS loader. Sở dĩ gọi là Optional Header là vì một số file như object files không cần nó, tuy nhiên image files (VD: các file .exe) thì cần nó

## Section Table
Ngay sau Optional Header là Section Table, đây là một mảng của Image Section Headers.
Mỗi header chứa thông tin về section mà nó hướng đến

## Sections
Sections là nơi mà nội dung thật sự của file được lưu trữ, bao gồm dữ liệu và tài nguyên mà chương trình sử dụng và cả code thật sự của chương trình. Mỗi section có một mục đính riêng.

---

**Kết luận**
Bài viết này cung cấp thông tin tổng quan cơ bản của một file PE và thông tin ngắn gọn về các phần chính là một file PE
Bài viết tới ta sẽ nói chi tiết hơn về từng phần này.



---



# Phần 2: DOS Header, DOS Stub và Rich Header

**Giới thiệu**
Trong phần 1, chúng ta đã có cái nhìn tổng quan về cấu trúc file PE. Trong phần này, ta sẽ nói về 2 phần đầu tiên của file PE - DOS Header và DOS Stub

Tôi sẽ dùng PE-bear làm PE viewer xuyên suốt series này.

---

## DOS Header

**Tổng Quan**
DOS Header (hay MS-DOS header) là một structure dài 64 bytes bắt đầu của file. Phần này không quan trọng đối với chức năng của file PE trên các hệ thống Windows hiện tại nhưng vẫn tồn tại vì các lí do tương thích với các hệ thống trước đấy.
Phần header này cho biết file này là một file thực thi MS-DOS 
-> Khi header này được load trên MS-DOS, phần DOS Stub được thực thi thay vì chương trình thật sự
Nếu như bạn load file thực thi trên MS-DOS mà không có phần header này thì file sẽ không được load và trả về generic error.

**Structure**
Như đã đề cập ở phần trước, đây là một structure 64 bytes, ta có thể xem nội dụng của structure này bằng cách xem định nghĩa structure `IMAGE_DOS_HEADER` từ thư viện `winnt.h`:
```Cpp=
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```
Structure này quan trọng với PE loader trên MS-DOS, tuy nhiên chỉ một số ít trường thông tin là quan trọng với PE loader trên Windows Systems nên ta sẽ chỉ nói đến các trường thông tin quan trọng của structure.

* **e_magic**: là trường thông tin đầu tiên của DOS Header với kiểu dữ liệu WORD (chiếm 2 bytes) và thường được gọi là magic number. Giá trị cố định là `0x5A4D` hoặc `MZ` trong ASCII. Đây là signature đánh dấu file là file thực thi MS-DOS 
* **e_lfanew**: Là trường thông tin cuối cùng của DOS header structure, được đặt ở offset `0x3C` và chứa offset bắt đầu của NT headers. Trường thông tin này quan trọng với PE loader trên Windows systems vì nó cho loader biết tìm file header ở đâu

Hình dưới đây là nội dung DOS header trong một file PE thật: 

![image](https://hackmd.io/_uploads/H1BFVnY36.png)

Ta có thể thấy rằng, trường thông tin đầu tiên của header là Magic number với giá trị cố định là `5A4D`.
Trường thông tin của header (ở offset `0x3C`) có tên là "File address of new exe header" và giá trị là `E8`, từ offset này ta sẽ tìm phần bắt đầu của NT headers như dự kiến:

![image](https://hackmd.io/_uploads/BkAnD3t3a.png)
---

## DOS Stub

**Tổng quan**
DOS Stub là một chương trình MS-DOS in ra một error message báo rằng file thực thi không tương thích với DOS và thoát.
Đây là cái được thực thi khi chương trình được load vào MS-DOS, error message mặc định là "This program cannot be run in DOS mode.", tuy nhiên message này có thể đổi trong quá trình compile.

Đó là tất cả những gì ta cần biết về DOS stub, ta không cần thật sự quan tâm đến nó. Nhưng hãy xem cách hoạt động của nó (j4f) :>>

**Phân tích**
Để có thể disassemble machine code của DOS stub, tôi copy hex của phần stub từ `PE-bear`, sau đó tạo một file mới bằng hex editor (`HxD`) và đặt tên là `dos-stub.exe`

Stub code:
```
0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20 6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00 88 2B 04 D3 CC 4A 6A 80 CC 4A 6A 80 CC 4A 6A 80 87 32 69 81 C8 4A 6A 80 87 32 6E 81 DB 4A 6A 80 87 32 6F 81 CB 4A 6A 80 87 32 6B 81 DF 4A 6A 80 CC 4A 6B 80 04 4A 6A 80 87 32 62 81 DC 4A 6A 80 87 32 95 80 CD 4A 6A 80 87 32 68 81 CD 4A 6A 80 52 69 63 68 CC 4A 6A 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

![image](https://hackmd.io/_uploads/SymFM6K3a.png)

Sau đó, tôi dùng `IDA` để disassemble file thực thi. Vì các chương trình MS-DOS là chương trình 16-bit nên tôi chọn `intel 8086` processor type và 16-bit disassembly mode.

![image](https://hackmd.io/_uploads/Sy6LXpthT.png)

Chương trình này khá là đơn giản, ta sẽ xem qua từng dòng
```
seg000:0000                 push    cs
seg000:0001                 pop     ds
```
Dòng đầu đẩy giá trị của `cs` vào stack và dòng thứ 2 để chuyển giá trị trên cùng của stack vào `ds`. Đây là một cách đặt giá trị của data segment sang cùng giá trị với code segment.
```
seg000:0002                 mov     dx, 0Eh
seg000:0005                 mov     ah, 9
seg000:0007                 int     21h             ; DOS - PRINT STRING
seg000:0007                                         ; DS:DX -> string terminated by "$"
```
Ba dòng này có chức năng in ra error message, dòng đầu đặt `dx` vào địa chỉ của chuỗi "This program cannot be run in DOS mode." (`0xE`), dòng thứ 2 đặt `ah` thành `9` và dòng cuối gọi interrupt `21h`.

Interrupt `21h` là một DOS interrupt (API call) có thể làm được rất nhiều thứ, nó lấy tham số xác định cái mà hàm sẽ thực thi và tham số đó được truyền vào thanh ghi `ah`.
Ta có thể thấy ở đây interrupt có giá trị là `9`, `9` là code của function in ra một chuỗi ra màn hình, hàm này lấy tham số - địa chỉ của string để in ra - được truyền vào thanh ghi `dx` như chúng ta đã thấy ở code.

Thông tin về DOS API có thể tìm thấy trên [Wikipedia](https://en.wikipedia.org/wiki/DOS_API).

```
seg000:0009                 mov     ax, 4C01h
seg000:000C                 int     21h             ; DOS - 2+ - QUIT WITH EXIT CODE (EXIT)
seg000:000C                                         ; AL = exit code
```
Ba dòng cuối cùng của chương trình gọi interrupt `21h` một lần nữa, lần này có một instruction `mov` đưa `0x4C01` vào `ax`. Instruction này đặt `al` là `0x01` và `ah` là `0x4c`.

`0x4c` là function code của hàm mà thoát với một error code, nó lấy error code từ `al`, trong trường hợp này là `1`.

Tổng kết lại, tất cả cái mà DOS stub làm là in ra một error message rồi thoát với code 1.

___

## Rich Header

Ta đã nói đến DOS Header và DOS Stub nhưng có một data chunk ta chưa nói đến nằm ở giữa DOS Stub và phần bắt đầu của NT Headers.

![image](https://hackmd.io/_uploads/Sk_ao6KnT.png)

Data chunk này thường được gọi là Rich Header, là một undocumented structure mà chỉ xuất hiện trong các file thực thi được build bằng Microsoft Visual Studio toolset.
Structure này giữ một vài metadata về các tools được dùng để build file thực thi như tên, loại và phiên bản cụ thể và build numbers của chúng.

Rich Header thực chất không phải là một phần của PE file format structure và có thể zeroed-out mà không can thiệp vào chức năng của file thực thi. Nó chỉ là một phần Microsoft thêm vào bất kì file thực thi nào được build bằng cách dùng Visual Studio toolset của họ.

Tôi chỉ biết về Rich Header vì tôi đã đọc reports về Olympic Destroyer malware. Dành cho những ai chưa biết, Olympic Destroyer malware là mã độc được viết và sử dụng bởi một threat group trong một lần cố gắng phá hoại Olympic Mùa Đông 2018.
Mã độc này có nhiều các flags giả được cố tình thêm vào để gây bối rối và phân bổ sai, một trong số false flags đó là Rich Header.
Tác giả của mã độc đã ghi đè Rich Header gốc trong file thực thi của mã độc bằng Rich Header của một mã độc khác có các thuộc tính của Lazarus threat group để mã độc nhìn giống như là Lazarus. 
Thông tin thêm có thể tìm thấy trong [Kaspersky's report](https://securelist.com/the-devils-in-the-rich-header/84348/).

Rich Header chứa một data chunk được XORed theo sau bởi một signature (`Rich`) và một giá trị checksum 32-bit là XOR key.
Data được mã hóa chứa một DWORD signature `DanS`, 3 zeroed-out DWORDs để padding, sau đó là các cặp DWORD mỗi cặp đại diện cho một entry, mỗi entry giữ một toolname, build number và số lần sử dụng của nó.
Trong mỗi cặp DWORD, cặp đầu tiên giữ type ID hoặc product ID trong high WORD và build ID trong low WORD, cặp thứ 2 giữ số lần sử dụng

PE-bear tự động parse Rich Header:

![image](https://hackmd.io/_uploads/S1DKECF2a.png)

Như ta thấy, `DanS` signature là thứ đầu tiền ở trong structure, sau đó là 3 zeroed-out DWORDs và sau đó là các entries.
Ta có thể thấy lần lượt các tools và phiên bản Visual Studio của product và build IDs. 

![image](https://hackmd.io/_uploads/Hy4KrRKna.png)

Tôi đã viết một script để tự parse header này. Đây là một quá trình đơn giản, tất cả chúng ta cần làm là XOR data, rồi đọc các cặp entry và dịch chúng.

Rich Header data:
```
88 2B 04 D3 CC 4A 6A 80 CC 4A 6A 80 CC 4A 6A 80 87 32 69 81 C8 4A 6A 80 87 32 6E 81 DB 4A 6A 80 87 32 6F 81 CB 4A 6A 80 87 32 6B 81 DF 4A 6A 80 CC 4A 6B 80 04 4A 6A 80 87 32 62 81 DC 4A 6A 80 87 32 95 80 CD 4A 6A 80 87 32 68 81 CD 4A 6A 80 52 69 63 68 CC 4A 6A 80
```

Script:
```python=
import textwrap

def xor(data, key):
	return bytearray( ((data[i] ^ key[i % len(key)]) for i in range(0, len(data))) )

def rev_endiannes(data):
	tmp = [data[i:i+8] for i in range(0, len(data), 8)]
	
	for i in range(len(tmp)):
		tmp[i] = "".join(reversed([tmp[i][x:x+2] for x in range(0, len(tmp[i]), 2)]))
	
	return "".join(tmp)

data = bytearray.fromhex("882B04D3CC4A6A80CC4A6A80CC4A6A8087326981C84A6A8087326E81DB4A6A8087326F81CB4A6A8087326B81DF4A6A80CC4A6B80044A6A8087326281DC4A6A8087329580CD4A6A8087326881CD4A6A8052696368CC4A6A80")
key  = bytearray.fromhex("CC4A6A80")

rch_hdr = (xor(data,key)).hex()
rch_hdr = textwrap.wrap(rch_hdr, 16)

for i in range(2,len(rch_hdr)):
	tmp = textwrap.wrap(rch_hdr[i], 8)
	f1 = rev_endiannes(tmp[0])
	f2 = rev_endiannes(tmp[1])
	print("{} {} : {}.{}.{}".format(f1, f2, str(int(f1[4:],16)), str(int(f1[0:4],16)), str(int(f2,16)) ))
```

![image](https://hackmd.io/_uploads/SJMFhRFhp.png)

Lưu ý: Vì data được biểu diễn dưới dạng little-endian nên tôi phải đảo ngược thứ tự byte.

Sau khi chạy script, ta có thể thấy ouput giống như PE-bear interpretation, nghĩa là script hoạt động chuẩn.

Việc dịch các giá trị sang tool types và phiên bản thực tế là vấn đề thu thập các giá trị từ bản cài đặt Visual Studio thực tế.

Tôi đã kiểm tra source code của `bearparser` (the parser used in PE-bear) và tôi tìm được các [comments](https://github.com/hasherezade/bearparser/blob/master/parser/pe/RichHdrWrapper.cpp) đề cập đến những giá trị này được lấy từ đâu.

---

## Kết luận
Trong bài viết này, ta đã nói về 2 phần đầu tiên của file PE - DOS Header và DOS Stub, ta đã xem các trường thông tin của DOS header structure đồng thời dịch ngược DOS stub program.
Ta cũng đã tìm hiểu Rich Header, một structure không cần thiết của PE file format nhưng đáng để kiểm tra.

Hình ảnh dưới tổng hợp lại những gì chúng ta đã đề cập trong bài viết này:

![image](https://hackmd.io/_uploads/By6NZJ92p.png)

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
* **NumberOfSections**: Trường thông tin này giữ số lượng sections (hoặc là số lượng section headers aka[^1] kích thước của section table).
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
  * **0x107**: định danh image là image ROM[^2] 
  Giá trị của trường thông tin này là cái để xác định file thực thi là 32-bit hay 64-bit, Windows PE loader bỏ qua trường thông tin`IMAGE_FILE_HEADER.Machine`.
* **MajorLinkerVersion** và **MinorLinkerVersion**: Linker đến số phiên bản major và minor
* **SizeOfCode**: Trường thông tin này giữ kích thước của code section (`.text`), hay tổng số của tất cả code sections nếu như có nhiều sections.
* **SizeOfInitializedData**: Trường thông tin này giữ kích thước của section data được khởi tạo (`.data`) hoặc tổng số các sections tương tự.
* **SizeOfUninitializedData**: Trường thông tin này giữ kích thước của section dữ liệu không được khởi tạo (`.bss`) hoặc tổng số các sections tương tự.
* **AddressOfEntryPoint**: địa chỉ RVA của entry point khi file được load vào memory. Documentation nêu rõ rằng đối với program images, địa chỉ tương đối này trỏ đến địa chỉ bắt đầu và với drivers thiết bị nó trỏ đến hàn khởi tạo. Đối với DLLs thì entry point là một thông tin optional và trong trường hợp không có entry point thì trường `AddressOfEntryPoint` được đặt là `0`. 
* **BaseOfCode**: một địa chỉ RVA của phần bắt đầu của code section khi file được load vào memory.
* **BaseOfData (PE32 Only)**: một địa chỉ RVA của phần bắt đầu của data section khi file được load vào memory.
* **ImageBase**: Trường thông tin này chứa địa chỉ ưu tiên của byte đầu tiền của image khi được load vào memory, giá trị này phải là bội số của 64K. Vì các biện pháp bảo vệ memory như ASLR và rất nhiều lý do khác, địa chỉ được chỉ định bởi trường thông tin này không được sử dụng. Trong trường hợp này, PE loader chọn một khoảng memory chưa được sử dụng để load image vào, sau khi load vào địa chỉ đó, loader sẽ thực hiện một process gọi là relocating - sửa các constant address[^3] ở trong image để hoạt động với image base mới. Có một section chứa thông tin về các vị trí sẽ cần phải sửa nếu như cần relocation, section này là relocation section (`.reloc`), ta sẽ tìm hiểu thêm trong bài viết sau. 
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


---


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


---


# Phần 5: PE Imports (Import Directory Table, ILT[^6], IAT[^7])

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


---


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

[^1]: also knowns as
[^2]: Read Only Memory
[^3]: địa chỉ cố định
[^4]: Relative Virtual Address
[^5]: Common Object File Format
[^6]: Import Lookup Table
[^7]: Import Address Table
[^8]: Import Name Table
