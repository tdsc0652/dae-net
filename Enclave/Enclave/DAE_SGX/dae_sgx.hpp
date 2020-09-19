#ifndef _DAE_SGX_H
#define _DAE_SGX_H

#include <stdlib.h>
#include <assert.h>

#if defined(__cplusplus)
extern "C" {
#endif

void printf(const char *fmt, ...);
void log_err(int op, const char *fmt, ...);
void log_notice(int op, const char *fmt, ...);
void log_info(int op, const char *fmt, ...);
void log_warn(int op, const char *fmt, ...);
void puts(const char *s);

uint32_t sgx_randombytes_random();
int sgx_rand();
void sgx_srand();
int sgx_socket();
int sgdx_bind();
int sgx_pthread_create_call_back_func1(void (*fn)(void *), int num, void *port, size_t port_len);
int sgx_pthread_detach(int pid);
int sgx_clock_gettime(clockid_t clk_id, struct timespec *tp, int n);
void sgx_exit(int exit_status);
//void printf(const char *fmt, ...);

#if defined(__cplusplus)
}
#endif

#define LOG_DEBUG   7
/** Info-level severity: for messages that appear frequently during normal
 * operation. */
#define LOG_INFO    6
/** Notice-level severity: for messages that appear infrequently
 * during normal operation; that the user will probably care about;
 * and that are not errors.
 */
#define LOG_NOTICE  5
/** Warn-level severity: for messages that only appear when something has gone
 * wrong. */
#define LOG_WARN    4
/** Error-level severity: for messages that only appear when something has gone
 * very wrong, and the Tor process can no longer proceed. */
#define LOG_ERR     3

//#endif

/* Logging domains */

/** Catch-all for miscellaneous events and fatal errors. */
#define LD_GENERAL  (1u<<0)
/** The cryptography subsystem. */
#define LD_CRYPTO   (1u<<1)
/** Networking. */
#define LD_NET      (1u<<2)
/** Parsing and acting on our configuration. */
#define LD_CONFIG   (1u<<3)
/** Reading and writing from the filesystem. */
#define LD_FS       (1u<<4)
/** Other servers' (non)compliance with the Tor protocol. */
#define LD_PROTOCOL (1u<<5)
/** Memory management. */
#define LD_MM       (1u<<6)
/** HTTP implementation. */
#define LD_HTTP     (1u<<7)
/** Application (socks) requests. */
#define LD_APP      (1u<<8)
/** Communication via the controller protocol. */
#define LD_CONTROL  (1u<<9)
/** Building, using, and managing circuits. */
#define LD_CIRC     (1u<<10)
/** Hidden services. */
#define LD_REND     (1u<<11)
/** Internal errors in this Tor process. */
#define LD_BUG      (1u<<12)
/** Learning and using information about Tor servers. */
#define LD_DIR      (1u<<13)
/** Learning and using information about Tor servers. */
#define LD_DIRSERV  (1u<<14)
#define LD_OR       (1u<<15)
/** Generic edge-connection functionality. */
#define LD_EDGE     (1u<<16)
#define LD_EXIT     LD_EDGE
/** Bandwidth accounting. */
#define LD_ACCT     (1u<<17)
/** Router history */
#define LD_HIST     (1u<<18)
/** OR handshaking */
#define LD_HANDSHAKE (1u<<19)
/** Heartbeat messages */
#define LD_HEARTBEAT (1u<<20)
/** Abstract channel_t code */
#define LD_CHANNEL   (1u<<21)
/** Scheduler */
#define LD_SCHED     (1u<<22)
/** Number of logging domains in the code. */
#define N_LOGGING_DOMAINS 23

/** This log message is not safe to send to a callback-based logger
 * immediately.  Used as a flag, not a log domain. */
#define LD_NOCB (1u<<31)
/** This log message should not include a function name, even if it otherwise
 * would. Used as a flag, not a log domain. */
#define LD_NOFUNCNAME (1u<<30)

#endif /* !_ENCLAVE_H_ */
