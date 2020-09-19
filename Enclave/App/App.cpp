#include <string>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <sodium.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <thread>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include "RelayConfig.hpp"

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <grp.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <sys/sysctl.h>
#include <sys/epoll.h>

#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <ctype.h>
#include <sys/stat.h>
#include <stdarg.h>

#include <map>
#include <list>
#include <signal.h>
#include <sys/time.h>
#include <sys/timeb.h>

#include <limits.h>
#include <glog/logging.h>
#include <event2/event.h>

#include <chrono>
using namespace std::chrono;

#ifdef EVAL_OCALL_COUNT
int ocall_num;
#endif

sgx_enclave_id_t global_eid = 0;

struct event_base *g_base = event_base_new();

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

void ocall_sgx_sleep(unsigned int s){
    sleep(s);
}
void ocall_sgx_srand(){
    srand(time(NULL));
}

int ocall_sgx_rand(){
    return rand();
}
int ocall_sgx_socket(int af, int type, int protocol){
    return socket(af, type, protocol);
}
int ocall_sgx_bind(int fd, const struct sockaddr *addr, int len){
    return bind(fd, addr, len);
}

void ocall_sgx_libevent_start(){
    LOG(INFO) << "start loop";
    std::thread([](){
        event_base_loop(g_base, 0);
    }).detach();
    LOG(INFO) << "return ";
}
static struct timespec start;
static bool is_bootstrap = true;
static int bootstrap_time = 20; //s
static int d_p2p_time_after = 2; //s
void _p2p_maintain_task(int sock, short s, void *arg){
    char **args = (char**)arg;
    struct event* ev = (struct event*) args[0];
    struct timeval *next = (struct timeval*)args[1];
    if (is_bootstrap) {
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        if (now.tv_sec - start.tv_sec > bootstrap_time) {
            is_bootstrap = false;
            next->tv_sec = d_p2p_time_after;
            next->tv_usec = 0;
        }
    }
    ecall_p2p_maintain_task(global_eid);
    event_add(ev, next);
}

void ocall_sgx_addevent_p2p_maintain_task(struct timeval *interval, size_t n, int boottime){
    LOG(INFO) << "sgx_addevent_p2p_maintain_task";
    bootstrap_time = boottime;
    char **arg = new char*[2]; //delete?
    struct event *ev = event_new(g_base, -1, 0, _p2p_maintain_task, arg);

    arg[0] = (char*)ev;
    arg[1] = (char*)interval;

    event_add(ev, interval);
    clock_gettime(CLOCK_REALTIME, &start);
}

// run once
void _p2p_joined_successful_once(int sock, short s, void *arg){
    ecall_p2p_joined_successful_once(global_eid);
    auto ev = (struct event *)arg;
    delete ev;
}

void ocall_sgx_addevent_p2p_joined_successful_once(struct timeval *interval, size_t n){
    struct event *ev = event_new(g_base, -1, 0, _p2p_joined_successful_once, ev);
    event_add(ev, interval);
}

// run repeatedly
void _p2p_fetch_successor_list(int sock, short s, void *arg){
    ecall_p2p_fetch_successor_list(global_eid);
}

void ocall_sgx_addevent_p2p_fetch_successor_list(struct timeval * interval, size_t n){
    struct event *ev = event_new(g_base, -1, EV_PERSIST, _p2p_fetch_successor_list, NULL);
    event_add(ev, interval);

}
void _p2p_check_successor_failure_once(int, short, void *arg){
    ecall_p2p_check_successor_failure_once(global_eid);
    auto ev = (struct event *)arg;
    delete ev;
}
void ocall_sgx_addevent_p2p_check_successor_failure_once(struct timeval *interval, size_t n){
    struct event *ev = event_new(g_base, -1, 0, _p2p_check_successor_failure_once, ev);
    event_add(ev, interval);
}
void _p2p_check_predecessor_failure_once(int sock, short s, void *arg){
    ecall_p2p_check_predecessor_failure_once(global_eid);
    auto ev = (struct event *)arg;
    delete ev;
}
void ocall_sgx_addevent_p2p_check_predecessor_failure_once(struct timeval *interval, size_t n){
    struct event *ev = event_new(g_base, -1, 0, _p2p_check_predecessor_failure_once, ev);
    event_add(ev, interval);
}
void _p2p_verify_successor_failure_once(int sock, short s, void *arg){
    ecall_p2p_verify_successor_failure_once(global_eid);
    auto ev = (struct event *)arg;
    delete ev;
}
void ocall_sgx_addevent_p2p_verify_successor_failure_once(struct timeval *interval, size_t n){
    struct event *ev = event_new(g_base, -1, 0, _p2p_verify_successor_failure_once, ev);
    event_add(ev, interval);
}
void _p2p_verify_predecessor_failure_once(int sock, short s, void *arg){
    ecall_p2p_verify_predecessor_failure_once(global_eid);
    auto ev = (struct event *)arg;
    delete ev;
}
void ocall_sgx_addevent_p2p_verify_predecessor_failure_once(struct timeval *interval, size_t n){
    struct event *ev = event_new(g_base, -1, 0, _p2p_verify_predecessor_failure_once, ev);
    event_add(ev, interval);
}

void _shuffle_send_batch(int sock, short s, void *arg){
    ecall_shuffle_send_batch(global_eid);
}

void ocall_sgx_shuffle_send_batch(struct timeval *interval, size_t n){
    struct event *ev = event_new(g_base, -1, EV_PERSIST, _shuffle_send_batch, NULL);
    event_add(ev, interval);
}
void _shuffle_start(int sock, short s, void *arg){
    ecall_shuffle_start(global_eid);
    auto ev = (struct event *)arg;
    delete ev;
}
void ocall_sgx_shuffle_start(struct timeval *interval, size_t n){
    struct event *ev = event_new(g_base, -1, 0, _shuffle_start, ev);
    event_add(ev, interval);
}

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <glog/logging.h>
void ocall_sgx_exit(int e) {
	exit(e);
}

void ocall_sgx_run_as_daemon() {

    pid_t pid;

    /* Fork off the parent process */
    pid = fork();

    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* On success: The child process becomes session leader */
    if (setsid() < 0)
        exit(EXIT_FAILURE);

    /* Catch, ignore and handle signals */
    //TODO: Implement a working signal handler */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    /* Fork off for the second time*/
    pid = fork();

    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* Set new file permissions */
    umask(0);

    /* Change the working directory to the root directory */
    /* or another appropriated directory */
    // chdir("/");

    /* Close all open file descriptors */
    // int x;
    // for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
    // {
    //     close (x);
    // }

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    /* Open the log file */
    // openlog (logger.c_str(), LOG_PID, LOG_DAEMON);
    LOG(INFO) << "ok";
}

uint32_t ocall_sgx_randombytes_random(){
    return randombytes_random();
}
void print_error_message(sgx_status_t ret) {
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void) {
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

int ocall_sgx_clock_gettime(clockid_t clk_id, struct timespec *tp, int tp_size) {
	int retv = clock_gettime(clk_id, tp);
	return retv;
}

int ocall_sgx_sendto(int s, const void *msg, size_t len, int flags, const struct sockaddr *to, size_t tolen) {
	return sendto(s, (const char *)msg, len, flags, to, tolen);
}

//int ocall_sgx_recvfrom(int s, void *msg, int len, int flags, struct sockaddr *fr, int frlen, int *in_len)
int ocall_sgx_recvfrom(int s, void *msg, size_t len, int flags, struct sockaddr *fr, size_t frlen, int *in_len) {
//	return recvfrom(s, (char *)msg, len, flags, fr, in_len);
	return recvfrom(s, (char *)msg, len, flags, fr, (socklen_t *)in_len);
}

/** Wraps a void (*)(void*) function and its argument so we can
 * invoke them in a way pthreads would expect.
 */
typedef struct tor_pthread_data_t {
  void (*func)(void *);
  void *data;
} tor_pthread_data_t;
struct args_set_t
{
	void *args;
	int args_len;
};

void call_enclave_func1(void *args)
{
	sgx_status_t ret;
	struct args_set_t *args_set = (struct args_set_t *)args;
	if((ret = enclave_func_caller1(global_eid, args_set->args, args_set->args_len)) != SGX_SUCCESS) {
		printf("enclave_func_caller failed!: %x\n", ret);
		abort();
	}
	free(args_set->args);
	free(args);
}
/** Given a tor_pthread_data_t <b>_data</b>, call _data-&gt;func(d-&gt;data)
 * and free _data.  Used to make sure we can call functions the way pthread
 * expects. */
static void *
pthread_helper_fn(void *_data)
{
  tor_pthread_data_t *data = (tor_pthread_data_t *)_data;
  void (*func)(void*);
  void *arg;
  /* mask signals to worker threads to avoid SIGPIPE, etc */
  sigset_t sigs;
  /* We're in a subthread; don't handle any signals here. */
  sigfillset(&sigs);
//  sigfillset(&sigs);
  pthread_sigmask(SIG_SETMASK, &sigs, NULL);

  func = data->func;
  arg = data->data;
  free(_data);
  func(arg);
  return NULL;
}

int ocall_sgx_pthread_create_call_back_func1(void *args, size_t args_len)
{
  pthread_t thread;
  tor_pthread_data_t *d;

  d = (tor_pthread_data_t *)malloc(sizeof(tor_pthread_data_t));
  d->data = args;
  d->func = call_enclave_func1;

  return pthread_create(&thread, NULL, pthread_helper_fn, d);
}
int ocall_sgx_pthread_detach(int pid){
    return pthread_detach(pid);
}
int ocall_sgx_pthread_join(int pid){
    return pthread_join(pid, NULL);
}
/*
DAE_SGX : by yunpeng
*/
void ocall_log_info(const char* msg){
    LOG(INFO) << msg;
}

void ocall_log_warning(const char* msg){
    LOG(WARNING) << msg;
}

void ocall_log_error(const char* msg){
    LOG(ERROR) << msg;
}

void ocall_log_fatal(const char* msg){
    LOG(FATAL) << msg;
}

int ocall_sgx_inet_aton(const char *str, struct in_addr *inp, size_t n){
    return inet_aton(str, inp);
}
in_addr_t ocall_sgx_inet_addr(const char *str){
    return inet_addr(str);
}

void ocall_print_string(const char *str)
{	
	printf("%s", str);
}

// For eval
long ocall_sgx_clock(void)
{
	return clock();
}



/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    if (sodium_init() == -1) {
        abort();
    }
    (void)(argc);
    (void)(argv);

#if 0
  HMODULE hMod = GetModuleHandleA("Kernel32.dll");
  if (hMod) {
    typedef BOOL (WINAPI *PSETDEP)(DWORD);
    PSETDEP setdeppolicy = (PSETDEP)GetProcAddress(hMod,
                           "SetProcessDEPPolicy");
    if (setdeppolicy) setdeppolicy(1); /* PROCESS_DEP_ENABLE */
  }

        /* SGX-Tor: network_init() WSAStartup */
        WSADATA WSAData;
  int r;
  r = WSAStartup(0x101,&WSAData);
  if (r) {
    printf("Error initializing windows network layer: code was %d",r);
    return -1;
  }
        MEMORYSTATUSEX mse;
        memset(&mse, 0, sizeof(mse));
  	mse.dwLength = sizeof(mse);
        GlobalMemoryStatusEx(&mse);
#endif

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

/*------------------------------------------------------------------------------*/
/* Start DAE code */
        RelayConfig config = config.init_from_cmd(argc, argv);
        int res;
        DAE_start(global_eid, &res, &config, sizeof(config));
        sleep(10000);


/*------------------------------------------------------------------------------*/

#if 0 
    /* Utilize edger8r attributes */
    edger8r_array_attributes();
    edger8r_pointer_attributes();
    edger8r_type_attributes();
    edger8r_function_attributes();
    
    /* Utilize trusted libraries */
    ecall_libc_functions();
    ecall_libcxx_functions();
    ecall_thread_functions();
#endif

    /* Destroy the enclave */
done:
    sgx_destroy_enclave(global_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");

    printf("Enter a character before exit ...\n");
    getchar();
    return 0;
}

