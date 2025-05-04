[bits 16]
[org 0x7c00]

start:
    cli                     ; Disable interrupts
    cld                     ; Clear direction flag
    xor ax, ax             ; Clear AX
    mov ds, ax             ; Set data segment
    mov es, ax             ; Set extra segment
    mov ss, ax             ; Set stack segment
    mov bp, 0x7c00         ; Set base pointer
    lea sp, [bp-0x20]      ; Set stack pointer
    sti                     ; Enable interrupts

    ; Display system information
    mov si, system_info
    call print_string
    mov si, security_msg
    call print_string
    mov si, divider_msg
    call print_string

    mov ax, 0x1fe0         ; Set new segment address
    mov es, ax             ; Set extra segment
    mov si, bp             ; Set source address
    mov di, bp             ; Set destination address
    mov cx, 0x100          ; Set counter (256 words)
    rep movsw              ; Copy code
    jmp 0x1fe0:next        ; Jump to new location

next:
    mov ds, ax             ; Set data segment
    mov ss, ax             ; Set stack segment
    xor ax, ax             ; Clear AX
    mov es, ax             ; Set extra segment
    lea di, [bp+0x1be]     ; Point to partition table
    jmp check_partition

check_partition:
    test byte [di], 0x80   ; Test active flag
    jnz active_part        ; If active partition, jump
    add di, 0x10           ; Next partition entry
    cmp di, 0x7dfe         ; End of partition table?
    jc check_partition     ; If not end, continue
    mov si, error_msg      ; If no active partition
    call print_string
    jmp $                  ; Infinite loop

active_part:
    cmp word [es:0x7dfe], 0xaa55  ; Check boot signature
    jnz error             ; If invalid boot sector, error
    mov bx, 0x55aa        ; Check extended INT 13h support
    mov ah, 0x41
    int 0x13
    jc error              ; If not supported, error
    cmp bx, 0xaa55
    jnz error
    test cl, 1
    jz error

    ; Stage1: Store parameters at fixed memory location 0x0500
    push es

    ; Set ES to 0x0000 (shared memory area start)
    mov ax, 0x0000
    mov es, ax

    ; Write cylinder and sector numbers
    mov ax, [di+2]        ; Read cylinder/sector from partition table
    mov [es:0x0500], ax   ; Write to shared area offset 0x0500

    ; Write head number
    mov ax, [di+1]        ; Read head number from partition table
    mov [es:0x0502], ax   ; Write to shared area offset 0x0502

    ; Write drive number
    mov al, [boot_drive]  ; Read boot drive number
    mov [es:0x0504], al   ; Write to shared area offset 0x0504

    ; Restore ES segment register
    pop es

    ; Print parameters to pass to Stage2
    mov si, params_msg
    call print_string

    ; Print cylinder and sector numbers
    mov ax, [di+2]
    call print_hex
    mov si, comma_msg
    call print_string

    ; Print head number
    mov ax, [di+1]
    call print_hex
    mov si, comma_msg
    call print_string

    ; Print drive number
    mov al, [boot_drive]
    call print_hex
    mov si, crlf
    call print_string


    ; Load Stage2 to 0x2000
    mov ax, 0x2000          ; Stage2 load address segment
    mov es, ax
    xor bx, bx              ; Offset address = 0
    mov ah, 0x02            ; BIOS 13h - Read sectors
    mov al, 2               ; Read 2 sectors
    mov ch, 0               ; Cylinder 0
    mov cl, 2               ; Sector 2
    mov dh, 0               ; Head 0
    mov dl, [boot_drive]    ; Boot drive number
    int 0x13
    jc load_error

    ; Jump to Stage2
    jmp 0x2000:0 

load_error:
    mov si, stage2_load_error
    call print_string
    jmp $

error:
    mov si, error_msg
    call print_string
    jmp $

print_string:
    mov ah, 0x0E
.loop:
    lodsb
    test al, al
    jz .done
    int 0x10
    jmp .loop
.done:
    ret

print_newline:
    mov ah, 0x0e
    mov al, 13        ; Carriage return
    int 0x10
    mov al, 10        ; Line feed
    int 0x10
    ret

print_hex:
    push ax
    mov bx, 0x10          ; Base 16
    xor cx, cx
.next_digit:
    xor dx, dx
    div bx                ; AX divided by 16, result in AL
    push dx
    inc cx
    test ax, ax
    jnz .next_digit
.print_digit:
    pop dx
    add dl, '0'
    cmp dl, '9'
    jbe .output
    add dl, 'A' - '9' - 1
.output:
    mov ah, 0x0e
    mov al, dl
    int 0x10
    loop .print_digit
    pop ax
    ret

no_active_msg db "No active partition found!", 13, 10, 0
stage2_load_error db "Error loading Stage2!", 13, 10, 0
error_msg db "Error occurred!", 13, 10, 0
params_msg db "Params (Cylinder/Sector, Head, Drive): ", 0
comma_msg db ", ", 0
sp_msg db "Stack Pointer (SP): ", 0
crlf db 13, 10, 0
boot_drive db 0x80          ; Boot drive number

    times 446-($-$$) db 0   ; Fill up to partition table start

    ; Partition table (first partition is active)
    ;db 0x80, 0x01, 0x01, 0x00  ; Active partition flag
    ;db 0x0E, 0xFE, 0xFF, 0xFF  ; Partition type and CHS address
    ;db 0x3F, 0x00, 0x00, 0x00  ; Starting sector count
    ;db 0xC1, 0xFE, 0x0F, 0x00  ; Total sector count


    times 510-($-$$) db 0   ; Fill up to byte 510
dw 0xAA55               ; Boot signature

; Add system information messages
system_info      db "Sentinel DOS v1.0", 13, 10, 0
security_msg     db "Security Boot Loader", 13, 10, 0
divider_msg      db "====================", 13, 10, 0