#ifndef SECURITY_CHECK_H
#define SECURITY_CHECK_H

/* Security check module - Header file
 * Provides vector table and keyboard hook detection for DOS environment
 */

/* Initialize security checks and save initial system state
 * Returns: 0 on success, non-zero on error
 */
int initialize_security_check(void);

/* Perform security checks against saved initial state
 * Returns: 0 if system is secure, non-zero if security violation detected
 */
int perform_security_check(void);

/* Check if security checks are already initialized
 * Returns: 1 if initialized, 0 if not
 */
int is_security_initialized(void);

/* Get descriptive error message for the last security check failure
 * Returns: Pointer to error message string
 */
const char* get_security_error(void);

#endif /* SECURITY_CHECK_H */ 