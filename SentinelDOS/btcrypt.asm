; BTCRYPT.ASM - Bitcoin Private Key Encryption/Decryption for DOS
; Secure encryption tool for storing Bitcoin private keys in DOS environment
; Uses simple XOR encryption for maximum compatibility
; NASM compatible COM file format

; COM file uses a flat memory model with no sections
ORG 100h        ; COM file format starts at offset 100h

start:
    ; Setup segment registers (CRITICAL for COM programs)
    mov ax, cs
    mov ds, ax
    mov es, ax
    
    ; Clear screen for fresh start
    mov ax, 0003h
    int 10h
    
    ; Display program title
    mov ah, 09h
    mov dx, msg_title
    int 21h
    
    ; Display menu and get choice
main_menu:
    mov ah, 09h
    mov dx, msg_menu
    int 21h
    
    ; Get user selection
    mov ah, 01h
    int 21h
    
    ; Process choice
    cmp al, '1'
    je do_encrypt
    cmp al, '2'
    je do_decrypt
    cmp al, '3'
    je exit_prog
    
    ; Invalid choice - retry
    mov ah, 09h
    mov dx, msg_invalid
    int 21h
    jmp main_menu

; ===== ENCRYPT OPTION =====
do_encrypt:
    mov ah, 09h
    mov dx, msg_newline
    int 21h
    
    ; Get password
    mov ah, 09h
    mov dx, msg_password
    int 21h
    call get_password
    
    ; Used fixed filenames - no user input required
    mov ah, 09h
    mov dx, msg_encrypt
    int 21h
    
    ; Open source file (hardcoded as BTCKEY.TXT)
    mov ah, 3Dh
    mov al, 0          ; Read-only
    mov dx, filename_in
    int 21h
    jc error_open
    mov [filehandle], ax
    
    ; Create output file (hardcoded as BTCKEY.ENC)
    mov ah, 3Ch
    mov cx, 0          ; Normal attributes
    mov dx, filename_out
    int 21h
    jc error_create
    mov [outfilehandle], ax
    
    ; Add file signature (BTCK)
    mov ah, 40h
    mov bx, [outfilehandle]
    mov cx, 4
    mov dx, file_sig
    int 21h
    
    ; Process file in 512-byte chunks
encrypt_loop:
    ; Read chunk
    mov ah, 3Fh
    mov bx, [filehandle]
    mov cx, 512
    mov dx, buffer
    int 21h
    
    ; Check if done
    cmp ax, 0
    je encrypt_done
    
    ; Save bytes read
    mov [bytes_read], ax
    
    ; Encrypt buffer
    call encrypt_buffer
    
    ; Write encrypted chunk
    mov ah, 40h
    mov bx, [outfilehandle]
    mov cx, [bytes_read]
    mov dx, buffer
    int 21h
    
    ; Continue with next chunk
    jmp encrypt_loop
    
encrypt_done:
    ; Close files
    call close_files
    
    ; Show success message
    mov ah, 09h
    mov dx, msg_success
    int 21h
    
    ; Return to main menu after keypress
    call wait_key
    jmp main_menu

; ===== DECRYPT OPTION =====
do_decrypt:
    mov ah, 09h
    mov dx, msg_newline
    int 21h
    
    ; Get password
    mov ah, 09h
    mov dx, msg_password
    int 21h
    call get_password
    
    ; Used fixed filenames - no user input required
    mov ah, 09h
    mov dx, msg_decrypt
    int 21h
    
    ; Open encrypted file (hardcoded as BTCKEY.ENC)
    mov ah, 3Dh
    mov al, 0          ; Read-only
    mov dx, filename_out  ; note: reversed from encrypt
    int 21h
    jc error_open
    mov [filehandle], ax
    
    ; Verify file signature
    mov ah, 3Fh
    mov bx, [filehandle]
    mov cx, 4
    mov dx, buffer
    int 21h
    
    ; Check signature
    mov si, buffer
    mov di, file_sig
    mov cx, 4
    repe cmpsb
    jne error_signature
    
    ; Create output file (hardcoded as BTCKEY.DEC)
    mov ah, 3Ch
    mov cx, 0          ; Normal attributes
    mov dx, filename_dec
    int 21h
    jc error_create
    mov [outfilehandle], ax
    
    ; Process file in 512-byte chunks
decrypt_loop:
    ; Read chunk
    mov ah, 3Fh
    mov bx, [filehandle]
    mov cx, 512
    mov dx, buffer
    int 21h
    
    ; Check if done
    cmp ax, 0
    je decrypt_done
    
    ; Save bytes read
    mov [bytes_read], ax
    
    ; Decrypt buffer (uses same xor function)
    call encrypt_buffer
    
    ; Write decrypted chunk
    mov ah, 40h
    mov bx, [outfilehandle]
    mov cx, [bytes_read]
    mov dx, buffer
    int 21h
    
    ; Continue with next chunk
    jmp decrypt_loop
    
decrypt_done:
    ; Close files
    call close_files
    
    ; Show success message
    mov ah, 09h
    mov dx, msg_success
    int 21h
    
    ; Return to main menu after keypress
    call wait_key
    jmp main_menu

; ===== ERROR HANDLERS =====
error_open:
    mov ah, 09h
    mov dx, msg_error_open
    int 21h
    call wait_key
    jmp main_menu
    
error_create:
    mov ah, 09h
    mov dx, msg_error_create
    int 21h
    call close_files
    call wait_key
    jmp main_menu
    
error_signature:
    mov ah, 09h
    mov dx, msg_error_signature
    int 21h
    call close_files
    call wait_key
    jmp main_menu

; ===== PASSWORD INPUT =====
get_password:
    ; Clear password buffer
    mov di, password
    mov cx, 16
    mov al, 0
    rep stosb
    
    ; Read password
    mov di, password
    mov cx, 0
    
read_pw_loop:
    mov ah, 08h        ; Character input, no echo
    int 21h
    
    cmp al, 0Dh        ; Enter key
    je read_pw_done
    
    cmp al, 08h        ; Backspace
    je handle_backspace
    
    cmp cx, 15         ; Maximum length
    jae read_pw_loop
    
    ; Store character
    mov [di], al
    inc di
    inc cx
    
    ; Show asterisk
    mov ah, 02h
    mov dl, '*'
    int 21h
    
    jmp read_pw_loop
    
handle_backspace:
    ; Only if buffer not empty
    cmp cx, 0
    je read_pw_loop
    
    ; Remove character
    dec di
    dec cx
    
    ; Erase from screen
    mov ah, 02h
    mov dl, 08h        ; Backspace
    int 21h
    mov dl, ' '         ; Space
    int 21h
    mov dl, 08h        ; Backspace again
    int 21h
    
    jmp read_pw_loop
    
read_pw_done:
    mov byte [di], 0    ; Null terminate
    
    ; Print newline
    mov ah, 09h
    mov dx, msg_newline
    int 21h
    
    ret

; ===== ENCRYPTION FUNCTION =====
encrypt_buffer:
    push si
    push di
    push cx
    
    ; Setup for encryption
    mov si, buffer
    mov cx, [bytes_read]
    mov di, password
    
encrypt_byte:
    ; Check if at end of buffer
    cmp cx, 0
    je encrypt_buffer_done
    
    ; Check if at end of password
    cmp byte [di], 0
    jne use_password_char
    
    ; Reset to start of password
    mov di, password
    cmp byte [di], 0    ; Check if empty password
    jne use_password_char
    
    ; If empty password, use default byte
    mov al, 0FFh        ; Default encryption value
    jmp apply_xor
    
use_password_char:
    ; Get password character
    mov al, [di]
    inc di
    
apply_xor:
    ; Apply XOR encryption
    xor byte [si], al
    inc si
    dec cx
    jmp encrypt_byte
    
encrypt_buffer_done:
    pop cx
    pop di
    pop si
    ret

; ===== UTILITY FUNCTIONS =====
close_files:
    ; Close output file if open
    cmp word [outfilehandle], 0
    je skip_close_out
    mov ah, 3Eh
    mov bx, [outfilehandle]
    int 21h
    mov word [outfilehandle], 0
skip_close_out:

    ; Close input file if open
    cmp word [filehandle], 0
    je skip_close_in
    mov ah, 3Eh
    mov bx, [filehandle]
    int 21h
    mov word [filehandle], 0
skip_close_in:
    ret

wait_key:
    mov ah, 09h
    mov dx, msg_continue
    int 21h
    
    mov ah, 0
    int 16h
    
    ; Clear screen
    mov ax, 0003h
    int 10h
    ret

exit_prog:
    ; Exit to DOS
    mov ah, 4Ch
    int 21h

; ===== DATA SECTION =====
msg_title       db "BTCRYPT - Bitcoin Key Encryption v1.0", 0Dh, 0Ah
                db "=====================================", 0Dh, 0Ah
                db "Secure encryption for Bitcoin private keys", 0Dh, 0Ah, 0Dh, 0Ah, '$'
                
msg_menu        db "Select an option:", 0Dh, 0Ah
                db "1. Encrypt private key", 0Dh, 0Ah
                db "2. Decrypt private key", 0Dh, 0Ah
                db "3. Exit program", 0Dh, 0Ah
                db 0Dh, 0Ah, "Your choice: $"
                
msg_newline     db 0Dh, 0Ah, '$'
msg_password    db "Enter encryption password: $"
msg_encrypt     db 0Dh, 0Ah, "Encrypting BTCKEY.TXT to BTCKEY.ENC...", 0Dh, 0Ah, '$'
msg_decrypt     db 0Dh, 0Ah, "Decrypting BTCKEY.ENC to BTCKEY.DEC...", 0Dh, 0Ah, '$'
msg_success     db 0Dh, 0Ah, "Operation completed successfully!", 0Dh, 0Ah, '$'
msg_error_open  db 0Dh, 0Ah, "Error: Could not open input file!", 0Dh, 0Ah, '$'
msg_error_create db 0Dh, 0Ah, "Error: Could not create output file!", 0Dh, 0Ah, '$'
msg_error_signature db 0Dh, 0Ah, "Error: Invalid file format or wrong password!", 0Dh, 0Ah, '$'
msg_continue    db 0Dh, 0Ah, "Press any key to continue...$"
msg_invalid     db 0Dh, 0Ah, "Invalid option. Please try again.", 0Dh, 0Ah, '$'

; Fixed filenames to avoid input issues
filename_in     db "BTCKEY.TXT", 0
filename_out    db "BTCKEY.ENC", 0
filename_dec    db "BTCKEY.DEC", 0

; File signature for encrypted files
file_sig        db "BTCK"

; Variables
filehandle      dw 0
outfilehandle   dw 0
bytes_read      dw 0

; Buffers
password        times 17 db 0    ; 16 chars + null
buffer          times 512 db 0   ; File I/O buffer 