#include <pthread.h>
#include "uthash.h"

#define SERV_PORT "9000" // the port users will be connecting to
#define BACKLOG 128 // how many pending connections server queue will hold
#define CON_BUF_LEN 1024 // how many bytes server can receive at a time 
#define MAX_EPOLL_EVENTS 64 // Maximum number of polled events
#ifdef USE_AESD_CHAR_DEVICE
#define    OUT_FILE "/dev/aesdchar" 
#else
#define    OUT_FILE "/var/tmp/aesdsocketdata" // Where server writes out packets 
#endif

struct num_con_ctl {
    int num_con;
    pthread_mutex_t lock;
};

struct con_hash {
    int con_fd;
    UT_hash_handle hh;
};

struct con_q {
    struct con_hash *cons;
    pthread_mutex_t lock;
};

struct packet {
    int len;
    char *chars;
    struct packet *next;
};

struct rw_buf {
    struct packet *head;
    struct packet *tail;
    pthread_mutex_t lock;
};

struct con_l_elem {
    int con_fd;
    struct con_l_elem *next;
};

struct con_l {
    struct con_l_elem *head;
    struct con_l_elem *tail;
    pthread_mutex_t lock;
};

struct thread_ctl_elem {
    pthread_t threadh;
    uint8_t done;
    struct thread_ctl_elem *next;
};

struct con_read_args {
    int con_fd;
    struct rw_buf *recv_buf;
    struct con_l *disk_q;
    int outf_eid;
    int epfd;
    struct thread_ctl_elem *thctl;
    struct num_con_ctl *con_ctr;
};

struct file_ctl {
    int fd;
    pthread_mutex_t lock;
};

struct write_to_disk_args {
    struct rw_buf *recv_buf;
    struct file_ctl *out_fctl;
    struct con_l *disk_q;
    struct con_hash **send_q;
    int epfd;
    struct thread_ctl_elem *thctl;
    struct num_con_ctl *con_ctr;
};

struct con_write_args {
    struct file_ctl *out_fctl;
    int con_fd;
    int epfd;
    struct thread_ctl_elem *thctl;
    struct num_con_ctl *con_ctr;
};

struct write_time_args {
    struct file_ctl *out_fctl;
    struct thread_ctl_elem *thctl;
};

struct thread_ctl {
    struct thread_ctl_elem *head;
    int threadc;
};
