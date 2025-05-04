/* security_check.c - Anti-tampering protection module
 * For the QuantumVault Decryption component
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dos.h>
#include <conio.h>
#include <stdarg.h>  /* For va_list, va_start, va_end */
#include "security_check.h"

/* Constants */
#define MAX_INTERRUPT_CHECK 0x30    /* Check interrupts 0x00-0x2F */
#define KEYBOARD_INT_9      0x09    /* Keyboard hardware interrupt */
#define KEYBOARD_INT_16     0x16    /* Keyboard BIOS interrupt */
#define TIMER_INT_8         0x08    /* Timer interrupt */
#define DOS_INT_21          0x21    /* DOS API interrupt */

/* Internal state */
static int security_initialized = 0;
static unsigned long original_vectors[MAX_INTERRUPT_CHECK];
static unsigned long original_keyboard_vec9 = 0;
static unsigned long original_keyboard_vec16 = 0;
static char last_error_message[128] = {0};

/* Internal function prototypes */
static unsigned long get_interrupt_vector(int interrupt_num);
static int check_vector_table_integrity(void);
static int detect_keyboard_hooks(void);
static int detect_timer_hook(void);
static void set_error(const char* format, ...);

/* API Implementation */

int initialize_security_check(void) {
    int i;
    
    /* Already initialized? */
    if (security_initialized) {
        return 0;
    }
    
    /* Save original interrupt vectors */
    for (i = 0; i < MAX_INTERRUPT_CHECK; i++) {
        original_vectors[i] = get_interrupt_vector(i);
    }
    
    /* Save specific vectors we're interested in */
    original_keyboard_vec9 = original_vectors[KEYBOARD_INT_9];
    original_keyboard_vec16 = original_vectors[KEYBOARD_INT_16];
    
    security_initialized = 1;
    return 0;
}

int perform_security_check(void) {
    /* Make sure we're initialized */
    if (!security_initialized) {
        set_error("Security check not initialized");
        return -1;
    }
    
    /* Check interrupt vector table */
    if (check_vector_table_integrity() != 0) {
        /* Error message already set by check function */
        return 1;
    }
    
    /* Check for keyboard hooks */
    if (detect_keyboard_hooks() != 0) {
        /* Error message already set by check function */
        return 2;
    }
    
    /* Check for timer hook (often used for TSR) */
    if (detect_timer_hook() != 0) {
        /* Error message already set by check function */
        return 3;
    }
    
    /* All checks passed */
    return 0;
}

int is_security_initialized(void) {
    return security_initialized;
}

const char* get_security_error(void) {
    return last_error_message;
}

/* Internal Implementation */

/* Get interrupt vector using DJGPP inline assembly */
static unsigned long get_interrupt_vector(int interrupt_num) {
    unsigned long vector = 0;
    
    /* Properly formatted GCC inline assembly for accessing real-mode IVT */
    __asm__ __volatile__ (
        "pushl %%ebx\n\t"
        "movl %1, %%ebx\n\t"          /* Load interrupt number to EBX */
        "shll $2, %%ebx\n\t"          /* Multiply by 4 to get offset in IVT */
        "xorl %%eax, %%eax\n\t"       /* Clear EAX for segment 0000 */
        "movl $0, %%eax\n\t"
        "movl %%eax, %%fs\n\t"        /* FS = 0000 for real mode IVT access */
        "movl %%fs:(%%ebx), %%eax\n\t" /* Get vector from IVT */
        "movl %%eax, %0\n\t"          /* Store result to output variable */
        "popl %%ebx"                  /* Restore EBX register */
        : "=rm" (vector)              /* Output: vector in memory or register */
        : "g" (interrupt_num)         /* Input: interrupt number (general operand) */
        : "eax", "memory", "cc"       /* Clobbered registers */
    );
    
    return vector;
}

/* Check if interrupt vectors have been modified */
static int check_vector_table_integrity(void) {
    int i;
    unsigned long current_vector;
    
    for (i = 0; i < MAX_INTERRUPT_CHECK; i++) {
        /* Skip certain interrupts that might be legitimately hooked */
        if (i == 0x23 || i == 0x24) continue;  /* CTRL+C and Critical Error */
        
        /* Get current vector */
        current_vector = get_interrupt_vector(i);
        
        /* Compare with original */
        if (current_vector != original_vectors[i]) {
            set_error("Interrupt vector 0x%02X modified (0x%08lX != 0x%08lX)", 
                      i, current_vector, original_vectors[i]);
            return 1;
        }
    }
    
    return 0;
}

/* Detect keyboard hooks */
static int detect_keyboard_hooks(void) {
    unsigned long current_vec9, current_vec16;
    
    /* Check INT 9h (Keyboard Hardware) */
    current_vec9 = get_interrupt_vector(KEYBOARD_INT_9);
    if (current_vec9 != original_keyboard_vec9) {
        set_error("Keyboard interrupt (INT 9h) hooked (0x%08lX != 0x%08lX)",
                 current_vec9, original_keyboard_vec9);
        return 1;
    }
    
    /* Check INT 16h (Keyboard BIOS) */
    current_vec16 = get_interrupt_vector(KEYBOARD_INT_16);
    if (current_vec16 != original_keyboard_vec16) {
        set_error("Keyboard BIOS interrupt (INT 16h) hooked (0x%08lX != 0x%08lX)",
                 current_vec16, original_keyboard_vec16);
        return 1;
    }
    
    /* Additional check for keyboard buffer tampering could be added here */
    
    return 0;
}

/* Detect timer hook (common for TSRs) */
static int detect_timer_hook(void) {
    unsigned long current_timer = get_interrupt_vector(TIMER_INT_8);
    
    if (current_timer != original_vectors[TIMER_INT_8]) {
        set_error("Timer interrupt (INT 8h) hooked (0x%08lX != 0x%08lX)",
                 current_timer, original_vectors[TIMER_INT_8]);
        return 1;
    }
    
    return 0;
}

/* Set error message */
static void set_error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vsprintf(last_error_message, format, args);
    va_end(args);
} 