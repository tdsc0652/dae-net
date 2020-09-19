//
// Created by maxxie on 16-7-19.
//

#ifndef APP_SHARPVPN_SHARP_H__
#define APP_SHARPVPN_SHARP_H__


#include <sodium.h>
#include <unistd.h>
//#include <chrono>
//#include <queue>
#include <time.h>
#include <sys/time.h>

//typedef std::string dev_type;

//namespace c_file {
//    extern "C" ssize_t read(int __fd, void *__buf, size_t __nbytes);
//    extern "C" ssize_t write(int __fd, const void *__buf, size_t __n);
//    extern "C" int socket (int __domain, int __type, int __protocol) __THROW;
//}

#define MAX(a, b) ((a) > (b))? (a) : (b)
#define MIN(a, b) ((a) < (b))? (a) : (b)

#define SYMMETRIC_KEY_LEN 128

#ifdef NO_GLOG
#include "PipeLogger.h"
#else
#endif
#define MAX_MTU 1024

#ifndef TARGET_WIN32
#define msleep(s) usleep((s) * 1000)
#endif // TARGET_LINUX

typedef uint64_t ring_id_t;

#endif //SHARPVPN_SHARPVPN_H
