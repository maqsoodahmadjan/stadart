/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <string.h>
#include <jni.h>
#include <sys/mman.h>
#include <android/log.h>
#include<sys/wait.h>
#include<linux/binder.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>
#include <assert.h>
#include<sys/socket.h>    //socket
#include<arpa/inet.h> //inet_addr

#define	SYS_ioctl          54
#define BILLION 1000000000L
#define RUN 10000

#include <android/log.h>
#define TAG "perf"

#ifndef NDEBUG
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, TAG,__VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG  , TAG,__VA_ARGS__)
#else
#define LOGV(...)
#define LOGD(...)
#endif

int (*open_fn)(const char *, int, ...);
int (*ioctl_fn)(int , int , ...);
ssize_t (*recv_fn)(int ,void *, size_t , int );
int (*connect_fn)(int, const struct sockaddr*, socklen_t);



void callMprotect(long xstart, long xend) {
    if (mprotect((void *) xstart, xend - xstart, PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
        LOGD("mprotect failed3: %s\n", strerror(errno));
    }
}


void TRAPME(){
    LOGD("chiamato TRAPME\n");
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        LOGD("ERROR opening socket");
    listen(sockfd,5);
    LOGD("chiamato listen\n");

}

//FILE* out_fd = NULL;
int out_fd = NULL;
void savetofile(char* path,uint64_t time)
{
    out_fd = open(path, O_RDWR | O_APPEND);
    const int n = snprintf(NULL, 0, "%llu", time);
    assert(n > 0);
    char buf[n+1];
    int c = snprintf(buf, n+1, "%llu", time);
    assert(buf[n] == '\0');
    assert(c == n);
    //LOGD("buf: %s\n", buf);
    write(out_fd, buf, strlen(buf)+1);
    write(out_fd,"\n", 1);
    close(out_fd);
    //fputs(buf,out_fd);
    //fflush(out_fd);
}

void test_ioctl()
{
    LOGD("test ioctl \n");
    const char *path = "/data/local/tmp/antani666";
    uint64_t diff;
    struct timespec start, end, spec;
    int i, fd, k;
    fd = open(path, O_RDWR | O_CREAT);
    /* now re-do this and measure CPU time */
    /* the time spent sleeping will not count (but there is a bit of overhead */
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);    /* mark start time */
    for (k = 0; k < RUN; k++)
    {
        ioctl_fn(fd,1);
    }
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);		/* mark the end time */
    diff = BILLION * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
    LOGD("elapsed process CPU time = %llu nanoseconds\n", (long long unsigned int) diff);
    LOGD("ioctl single run took: %llu nanoseconds\n", (long long unsigned int) (diff / RUN));
    savetofile("/data/local/tmp/results_ioctl",diff / RUN);
    close(fd);

}


void tesf_open()
{
    LOGD("test open \n");
    const char *path = "/data/local/tmp/antani666";
    uint64_t diff;
    struct timespec start, end, spec;
    int i, fd, k;
    clock_getres(CLOCK_PROCESS_CPUTIME_ID, &spec);
    diff = BILLION * (spec.tv_nsec + spec.tv_sec);
    /* now re-do this and measure CPU time */
    /* the time spent sleeping will not count (but there is a bit of overhead */
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);    /* mark start time */
    for (k = 0; k < RUN; k++)
    {
        fd = open_fn(path, O_RDWR | O_CREAT);
    }
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);		/* mark the end time */
    close(fd);
    diff = BILLION * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
    LOGD("elapsed process CPU time = %llu nanoseconds\n", (long long unsigned int) diff);
    LOGD("open single run took: %llu nanoseconds\n", (long long unsigned int) (diff / RUN));
    savetofile("/data/local/tmp/results_open",diff / RUN);

}
int sock;
struct sockaddr_in server;

void test_connect()
{
    LOGD("test connect \n");
    uint64_t diff;
    struct timespec start, end, spec;
    int i, fd, k;
    clock_getres(CLOCK_PROCESS_CPUTIME_ID, &spec);
    diff = BILLION * (spec.tv_nsec + spec.tv_sec);
    /* now re-do this and measure CPU time */
    /* the time spent sleeping will not count (but there is a bit of overhead */
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);    /* mark start time */
    for (k = 0; k < RUN; k++)
    {
        connect_fn(sock , (struct sockaddr *)&server , sizeof(server));
    }
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);		/* mark the end time */
    diff = BILLION * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
    LOGD("elapsed process CPU time = %llu nanoseconds\n", (long long unsigned int) diff);
    LOGD("connect single run took: %llu nanoseconds\n", (long long unsigned int) (diff / RUN));
    savetofile("/data/local/tmp/results_connect",diff / RUN);
}
void init_fn()
{
    char buf[4]= {1};
    LOGD("init fn\n");
    open_fn = &open;
    ioctl_fn = &ioctl;
    recv_fn = &recv;
    connect_fn = &connect;
    //Create socket
    sock = socket(AF_INET , SOCK_STREAM , 0);
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons( 8888 );


}

#define SAMPLES 20

/* This is a trivial JNI example where we use a native method
 * to return a new VM String. See the corresponding Java source
 * file located at:
 *
 *   hello-jni/app/src/main/java/com/example/hellojni/HelloJni.java
 */
JNIEXPORT jstring JNICALL
Java_com_example_bladerunner_NativeCode_stringFromJNI( JNIEnv* env,
                                                  jobject thiz )
{
#if defined(__arm__)
    #if defined(__ARM_ARCH_7A__)
    #if defined(__ARM_NEON__)
      #if defined(__ARM_PCS_VFP)
        #define ABI "armeabi-v7a/NEON (hard-float)"
      #else
        #define ABI "armeabi-v7a/NEON"
      #endif
    #else
      #if defined(__ARM_PCS_VFP)
        #define ABI "armeabi-v7a (hard-float)"
      #else
        #define ABI "armeabi-v7a"
      #endif
    #endif
  #else
   #define ABI "armeabi"
  #endif
#elif defined(__i386__)
#define ABI "x86"
#elif defined(__x86_64__)
#define ABI "x86_64"
#elif defined(__mips64)  /* mips64el-* toolchain defines __mips__ too */
#define ABI "mips64"
#elif defined(__mips__)
#define ABI "mips"
#elif defined(__aarch64__)
#define ABI "arm64-v8a"
#else
#define ABI "unknown"
#endif
    struct binder_version vers;
    int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if(fd == -1){
        LOGD("chiamato mprotect\n");
        return (*env)->NewStringUTF(env, "Hello from JNI !  Compiled with ABI " ABI ".");
    }
    int ret = syscall(SYS_ioctl, fd, BINDER_VERSION, &vers);
    if(ret == -1){
        LOGD("chiamato mprotect\n");
        return (*env)->NewStringUTF(env, "Hello from JNI !  Compiled with ABI " ABI ".");
    }

    LOGD("versione binder: %d, userspace: %d \n", vers.protocol_version,
         BINDER_CURRENT_PROTOCOL_VERSION);
    close(fd);
/*
    uint8_t *buf = (uint8_t *) mmap(NULL, 1000, PROT_EXEC | PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mprotect(buf, 1000, PROT_READ|PROT_WRITE|PROT_EXEC) < 0) {
        LOGD("mprotect failed1: %s\n", strerror(errno));
    }

    long xstart = 0xb6c57000;
    long xend = 0xb6cc9000;
    //callMprotect(xstart,xend);
    TRAPME();
    LOGD("chiamato mprotect\n");
*/
    init_fn();
    int k;
    for(k=0;k<SAMPLES;k++){
        tesf_open();
        test_connect();
        test_ioctl();
        sleep(0.3);
    }
    close(sock);
    if(out_fd != NULL) close(out_fd);
    LOGD("TERMINATOOOOOOOO");
    return (*env)->NewStringUTF(env, "Hello from JNI !  Compiled with ABI " ABI ".");
}

