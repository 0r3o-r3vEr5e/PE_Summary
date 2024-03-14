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
