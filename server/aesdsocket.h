#define SERV_PORT "9000" // the port users will be connecting to
#define BACKLOG 10 // how many pending connections server queue will hold
#define MAX_CHLD 1024 // maximum connections the server can handle
#define RECV_BUF_LEN 1024 // how many bytes server can receive at a time 
#define OUT_FILE "/var/tmp/aesdsocketdata" // Where server writes out packets 

struct packet_buf {
    int buf_len;
    char *chars;
    struct packet_buf *next_buf;
};
