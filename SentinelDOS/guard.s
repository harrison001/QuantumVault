[org 0x100]

start:
    ; 检查是否已安装
    mov ax, 0x351F
    int 21h
    mov ax, es
    mov bx, cs
    cmp ax, bx
    je already_installed

    ; 保存原始向量
    call save_vectors
    
    ; 安装监控程序
    cli
    mov dx, monitor_handler
    mov ax, 0x251C
    int 21h
    
    ; 安装标识中断
    mov dx, guard_id
    mov ax, 0x251F
    int 21h
    sti

    ; 初始化检测计数器
    mov word [detect_count], 0

    ; 显示安装信息
    mov dx, install_msg
    mov ah, 09h
    int 21h

    ; 驻留程序
    mov dx, resident_end
    int 27h

monitor_handler:
    pushf
    pusha
    push ds
    push es
    
    ; 设置数据段
    mov ax, cs
    mov ds, ax
    
    ; 检查中断向量表
    xor ax, ax
    mov es, ax
    
    ; 检查关键中断
    mov bx, 9 * 4     ; 键盘中断
    call check_vector
    mov bx, 21h * 4   ; DOS中断
    call check_vector
    mov bx, 13h * 4   ; 磁盘中断
    call check_vector
    
    pop es
    pop ds
    popa
    popf
    iret

check_vector:
    push ax
    push dx
    
    mov ax, [es:bx]
    cmp ax, [original_vectors + bx]
    jne .modified
    mov ax, [es:bx + 2]
    cmp ax, [original_vectors + bx + 2]
    jne .modified
    
    pop dx
    pop ax
    ret

.modified:
    ; 增加检测计数
    inc word [detect_count]
    
    ; 显示警告
    push ax
    mov dx, warning_msg
    mov ah, 09h
    int 21h
    
    ; 显示被修改的中断号
    mov ax, bx
    shr ax, 2
    call print_number
    
    mov dx, newline
    mov ah, 09h
    int 21h
    pop ax
    
    ; 恢复原始向量
    cli
    mov ax, [original_vectors + bx]
    mov [es:bx], ax
    mov ax, [original_vectors + bx + 2]
    mov [es:bx + 2], ax
    sti
    
    pop dx
    pop ax
    ret

save_vectors:
    xor ax, ax
    mov es, ax
    mov si, 0
    mov di, original_vectors
    mov cx, 256
.save_loop:
    mov ax, [es:si]
    mov [di], ax
    mov ax, [es:si+2]
    mov [di+2], ax
    add si, 4
    add di, 4
    loop .save_loop
    ret

print_number:
    push ax
    push bx
    push cx
    push dx
    
    mov bx, 10
    mov cx, 0
    
.divide:
    xor dx, dx
    div bx
    push dx
    inc cx
    test ax, ax
    jnz .divide
    
.print:
    pop dx
    add dl, '0'
    mov ah, 02h
    int 21h
    loop .print
    
    pop dx
    pop cx
    pop bx
    pop ax
    ret

guard_id:
    iret

already_installed:
    mov dx, already_msg
    mov ah, 09h
    int 21h
    ret

; 数据段
detect_count     dw 0
original_vectors times 1024 db 0
install_msg     db 'Security Guard installed.', 0Dh, 0Ah, '$'
already_msg     db 'Security Guard already installed.', 0Dh, 0Ah, '$'
warning_msg     db '!!! WARNING: Interrupt vector modified - INT ', '$'
newline         db 0Dh, 0Ah, '$'

resident_end: