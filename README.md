# ShareFile
## Các chức năng của chương trình
1. Tạo cặp khóa bất đối xứng (tạo cho mình hoặc tạo cặp khóa giả lập người khác)
2. Mã hóa file, mã hóa secret key để giải mã bằng khóa công khai của những người tham gia chia sẻ file
3. Giải mã file

* `./Share.exe [option] arguments...`

## Tạo cặp khóa bất đối xứng
* `./Share.exe g "key-path"` <br>
* Ví dụ: 
`./Share.exe g "C:/Users/ADMIN/Key/MyKey"` <br>
* Tạo ra cặp khóa:
  1. Khóa công khai: C:/Users/ADMIN/Key/MyKey.pub
  2. Khóa bí mật: C:/Users/ADMIN/Key/MyKey.ppk

## Mã hóa file
* `./Share.exe e "source_file" "target_file" "pubkey_file"...`
  > Sinh ra secret key `k`, dùng các `pubkey_file` để mã hóa `k` và ghi file được mã hóa cùng với khóa được mã hóa vào `target_file`. <br>
* Ví dụ: <br>
`./Share.exe e "C:/Users/ADMIN/File/message.txt" "C:/Users/ADMIN/File/cipher.txt" "C:/Users/ADMIN/Key/MyKey.pub" "C:/Users/ADMIN/Key/A.pub" "C:/Users/ADMIN/Key/B.pub"` 

## Giải mã file
* `./Share.exe d "source_file" "target_file" "pubkey_file" "prikey_file"`
  > Giải mã `secret key` được mã hóa trong `source_file` bằng `public key` và `private key`, sau đó giải mã `source_file` bằng `secret_key` và ghi vào `target_file`. <br>
* Ví dụ: <br>
`./Share.exe d "C:/Users/ADMIN/File/cipher.txt" "C:/Users/ADMIN/File/original.txt" "C:/Users/ADMIN/Key/MyKey.pub" "C:/Users/ADMIN/Key/MyKey.ppk"` 
