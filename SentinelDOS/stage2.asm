[bits 16]
[org 0x0]                  ; Since we are executing at 0x2000:0

; Memory variable definitions (fixed memory transfer)
cylinder_sector equ 0x0500  ; Cylinder and sector numbers at 0x0000:0x0500
head           equ 0x0502  ; Head number at 0x0000:0x0502
drive          equ 0x0504  ; Drive number at 0x0000:0x0504
input_buf times 21 db 0   ; 20 bytes input buffer + 1 byte terminator
attempts db 3             ; Password attempt counter

;----------------------------------------
; Stage 2 Bootloader Entry
;----------------------------------------
stage2_start:
    ; Initialize segment registers
    mov ax, cs            ; CS is already 0x2000
    mov ds, ax            ; Set DS to code segment for string access
    mov ss, ax            ; Set stack segment to code segment
    mov sp, 0x7c00        ; Set stack pointer to high address
    mov es, ax            ; Set extra segment register

    call clear_screen     ; Clear screen
    call show_header      ; Show title

    call authenticate     ; Password verification
    call load_dos        ; Load DOS

    jmp 0x0000:0x7c00    ; Jump to DOS boot sector

;----------------------------------------
; Clear Screen
;----------------------------------------
clear_screen:
    mov ah, 0x00         ; Set display mode
    mov al, 0x03         ; 80x25 16-color text mode
    int 0x10
    ret

;----------------------------------------
; Show Header
;----------------------------------------
show_header:
    mov si, empty_line
    call print_string
    mov si, welcome_msg
    call print_string
    mov si, line_msg
    call print_string
    mov si, empty_line
    call print_string
    ret

;----------------------------------------
; Show Parameters
;----------------------------------------
show_params:
    mov si, params_msg
    call print_string
    mov ax, [cylinder_sector]
    call print_hex
    mov si, comma_msg
    call print_string
    mov ax, [head]
    call print_hex
    mov si, comma_msg
    call print_string
    mov al, [drive]
    call print_hex
    call print_newline
    mov si, empty_line
    call print_string
    ret

;----------------------------------------
; Password Authentication
;----------------------------------------
authenticate:
    mov byte [attempts], 3    ; Initialize attempt counter

.try_password:
    mov si, password_prompt
    call print_string

    call read_password
    call validate_password
    jnc .success             ; If validation successful (CF=0)

    ; Password error handling
    dec byte [attempts]      ; Decrease attempt counter
    jz .fail                 ; If attempts = 0, fail

    mov si, empty_line
    call print_string
    mov si, wrong_pass_msg
    call print_string
    mov si, attempts_msg
    call print_string
    mov al, [attempts]
    add al, '0'             ; Convert to ASCII
    mov ah, 0x0e
    int 0x10
    call print_newline
    mov si, empty_line
    call print_string
    jmp .try_password

.success:
    mov si, empty_line
    call print_string
    mov si, success_msg
    call print_string
    mov si, loading_msg
    call print_string
    ret

.fail:
    mov si, empty_line
    call print_string
    mov si, fail_msg
    call print_string
    mov si, halt_msg
    call print_string
    cli                     ; Disable interrupts
    hlt                     ; Halt system

;----------------------------------------
; Load DOS
;----------------------------------------
load_dos:
    ; Reset disk system
    xor ax, ax
    int 0x13            ; Reset disk system
    
    ; Set ES:BX to target buffer
    xor ax, ax
    mov es, ax          ; ES = 0x0000
    mov bx, 0x7c00      ; ES:BX = 0x0000:0x7C00
    
    ; Read correct CHS parameters from 0x0000:0x0500
    mov cx, [es:0x0500]  ; Read cylinder and sector numbers
    mov dh, byte [es:0x0502]  ; Read head number
    mov dl, byte [es:0x0504]  ; Read drive number
    
    ; Read DOS boot sector
    mov ax, 0x0201      ; AH=02(Read sectors), AL=01(1 sector)
    int 0x13
    jc error
    
    ; Jump directly to DOS, no copy needed
    ; Ensure correct segment registers
    xor ax, ax
    mov ds, ax          ; DS = 0
    mov es, ax          ; ES = 0
    mov ss, ax          ; SS = 0
    mov sp, 0x7c00      ; SP = 0x7C00
    
    ; Keep dl as drive number
    mov dl, 0x80        ; DL = Drive number (DOS needs this)
    
    ; Use far jump to ensure correct CS:IP
    jmp 0x0000:0x7c00   ; CS:IP = 0x0000:0x7C00

error:
    ; Restore DS to code segment for string access
    mov ax, cs
    mov ds, ax           ; DS = CS for string access
    
    mov si, empty_line
    call print_string
    mov si, read_error_msg
    call print_string
    mov si, error_code_msg
    call print_string
    mov al, ah          ; Error code
    call print_hex
    
    ; Display segment register values for debugging
    mov si, debug_regs
    call print_string
    
    mov ax, cs
    call print_hex
    mov si, comma_msg
    call print_string
    
    mov ax, ds
    call print_hex
    mov si, comma_msg
    call print_string
    
    mov ax, es
    call print_hex
    call print_newline
    
    cli
    hlt

;----------------------------------------
; String Printing Functions
;----------------------------------------
print_string:
    mov ah, 0x0e
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

read_password:
    mov di, input_buf
    xor cx, cx            ; Clear counter

read_password_loop:
    xor ah, ah            ; Read key
    int 0x16
    
    cmp al, 0x0d          ; Check for Enter key
    je read_password_done
    
    cmp al, 0x08          ; Check for Backspace key
    je handle_backspace
    
    cmp cx, 20            ; Check if buffer is full
    je read_password_loop
    
    mov [di], al          ; Save character
    inc di                ; Point to next position
    inc cx                ; Increment counter
    
    mov ah, 0x0e          ; Display asterisk
    mov al, '*'
    int 0x10
    jmp read_password_loop

handle_backspace:
    test cx, cx           ; Check if there are characters to delete
    jz read_password_loop
    dec di                ; Back up one character
    dec cx                ; Decrease counter
    
    mov ah, 0x0e          ; Display backspace sequence
    mov al, 0x08
    int 0x10
    mov al, ' '
    int 0x10
    mov al, 0x08
    int 0x10
    jmp read_password_loop

read_password_done:
    mov byte [di], 0      ; String terminator
    ret

validate_password:
    mov si, password      ; Correct password
    mov di, input_buf     ; Input password
    
.compare_loop:
    mov al, [si]         ; Load correct password character
    mov bl, [di]         ; Load input password character
    
    ; If both characters are 0 (string end), password matches
    test al, al
    jz .check_end
    
    ; Compare characters
    cmp al, bl
    jne .fail            ; If not equal, validation fails
    
    inc si               ; Move to next character
    inc di
    jmp .compare_loop

.check_end:
    ; Ensure input password also ends (prevent "sentinel123" from validating)
    test bl, bl
    jnz .fail
    
    ; Validation successful
    clc                  ; Clear carry flag to indicate success
    ret

.fail:
    stc                  ; Set carry flag to indicate failure
    ret

;----------------------------------------
; Data Section
;----------------------------------------
welcome_msg      db "Welcome to Sentinel OS Boot Loader v1.0", 13, 10, 0
line_msg         db "==========================================", 13, 10, 0
empty_line       db 13, 10, 0
password_prompt  db "Please enter password: ", 0
wrong_pass_msg   db "Access denied: Invalid password!", 13, 10, 0
attempts_msg     db "Remaining attempts: ", 0
success_msg      db "Access granted! Welcome to the system.", 13, 10, 0
loading_msg      db "Loading DOS operating system...", 13, 10, 0
fail_msg         db "System locked: Too many invalid attempts!", 13, 10, 0
halt_msg         db "System halted for security reasons.", 13, 10, 0
read_error_msg   db "Fatal Error: Unable to load DOS", 13, 10, 0
error_code_msg   db "Error code: ", 0
params_msg       db "System Parameters (CHS): ", 0
comma_msg        db ", ", 0
password         db "sentinel", 0     ; 8-byte password
debug_regs       db "CS,DS,ES: ", 0
debug_params    db "Reading DOS from (CHS): ", 0

