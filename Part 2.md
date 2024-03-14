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
