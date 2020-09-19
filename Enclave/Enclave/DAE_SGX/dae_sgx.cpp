#include "Enclave_t.h"
#include "Enclave.h"
#include "sgx_trts.h"
#include "orconfig.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctime>
#include <string>
#include "DAEService.hpp"
#include <ctype.h>
#include <map>
#include "sgx_tcrypto.h"
#include "sgx_thread.h"
#include <list>
#include "dae_sgx.hpp"
using namespace std;

void sgx_srand(){
	ocall_sgx_srand();
}

int sgx_rand(){
	int res = 0;
	if(ocall_sgx_rand(&res) != SGX_SUCCESS){
		return -1;
	}
	return res;
}
uint32_t sgx_randombytes_random(){
	uint32_t res;
	if(ocall_sgx_randombytes_random(&res) != SGX_SUCCESS){
		printf("sodium random error!");
		abort();
	}
	return res;
}

int sgx_clock_gettime(clockid_t clk_id, struct timespec *tp, int n){
	int res = -1;
	if(ocall_sgx_clock_gettime(&res, clk_id, tp, n) != SGX_SUCCESS){
		return -1;
	}	
	return res;
}
void sgx_exit(int exit_status){
	printf("sgx_exit: exit(%d) called!\n",exit_status);
	abort(); 
}

static void (* call_bacK_func1) (void *) = NULL;
//4
// OCALL make thread and call enclave function

int sgx_pthread_create_call_back_func1(void (*fn)(void *), int num, void *port, size_t port_len) 
{
	int retv;
	call_bacK_func1 = fn;
	sgx_status_t sgx_retv;

	if((sgx_retv = ocall_sgx_pthread_create_call_back_func1(&retv, port, port_len)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
int sgx_pthread_detach(int pid){
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_pthread_detach(&retv, pid)) != SGX_SUCCESS){
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}
int sgx_pthread_join(int pid){
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_pthread_join(&retv, pid)) != SGX_SUCCESS){
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}
	return retv;
}

// ECALL make thread and call enclave function
void enclave_func_caller1(void *args, int args_len)
{
	if(call_bacK_func1 != NULL) {
		call_bacK_func1(args);
	}
	else {
		printf("enclave_func_caller: cur_fn is NULL!!\n");
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif
}

int sgx_sendto(int s, const void *msg, int len, int flags, const struct sockaddr *to, int tolen)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_sendto(&retv, s, msg, len, flags, to, tolen)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
//20
//int sgx_recvfrom(int s, void *msg, int len, int flags, struct sockaddr *fr, int *in_len)
int sgx_recvfrom(int s, void *msg, int len, int flags, struct sockaddr *fr, int *in_len)
{
	int retv;
	sgx_status_t sgx_retv;
	if((sgx_retv = ocall_sgx_recvfrom(&retv, s, msg, len, flags, fr, *in_len, in_len)) != SGX_SUCCESS) {
		printf("OCALL FAILED!, Error code = %d\n", sgx_retv);
		abort();
	}

#ifdef EVAL_OCALL_COUNT
	ocall_num++;
#endif

	return retv;
}
void sgx_sleep(unsigned int s)
{
	ocall_sgx_sleep(s);
}

int DAE_start(void *config, size_t n){
	auto cfg = (RelayConfig*)config;
	ocall_log_info("in Enclave");
    if (cfg->daemon)
        ocall_sgx_run_as_daemon();

    DAEService *DAE_service = new DAEService(cfg);
	ocall_log_info("start");
    DAE_service->start();
	ocall_log_info("end");
	return DAE_service->node_id;
}

void printf(const char *fmt, ...)
{
	char buf[8192] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, 8192, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

void puts(const char *s)
{
	ocall_print_string(s);
	ocall_print_string("\n");
}

void log_err(int op, const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string("LOG_ERR: ");
	ocall_print_string(buf);
	ocall_print_string("\n");
}

void log_notice(int op, const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string("LOG_NOTICE: ");
	ocall_print_string(buf);
	ocall_print_string("\n");
}

void log_info(int op, const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string("LOG_INFO: ");
	ocall_print_string(buf);
	ocall_print_string("\n");
}

void log_warn(int op, const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string("LOG_WARN: ");
	ocall_print_string(buf);
	ocall_print_string("\n");
}
#if BYTE_ORDER == BIG_ENDIAN

#define HTONS(n) (n)
#define NTOHS(n) (n)
#define HTONL(n) (n)
#define NTOHL(n) (n)

#else

#define HTONS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#define NTOHS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))

#define HTONL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))

#define NTOHL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))
#endif

unsigned short sgx_htons(unsigned short hostshort)
{
	return HTONS(hostshort);
}

unsigned long sgx_htonl(unsigned long hostlong)
{
	return HTONL(hostlong);
}

unsigned short sgx_ntohs(unsigned short netshort)
{
	return NTOHS(netshort);
}

unsigned long sgx_ntohl(unsigned long netlong)
{
	return NTOHL(netlong);
}
