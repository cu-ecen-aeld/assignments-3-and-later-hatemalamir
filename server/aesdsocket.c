/******************************************************************************
* Copyright (C) 2025 by Hatem Alamir
*
* Redistribution, modification or use of this software in source or binary
* forms is permitted as long as the files maintain this copyright. Users are 
* permitted to modify this and use it to learn about the field of embedded
* software. Hatem Alamir is not liable for any misuse of this material. 
*
******************************************************************************/
/*
 * REFERENCE: https://beej.us/guide/bgnet/html/
 *
 * Main server module that does the following:
 * 1) Opens a stream socket bound to port 9000, failing and returning -1 if any of
 * the socket connection steps fail.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <syslog.h>
#include <fcntl.h>
#include "aesdsocket.h"
#include <sys/socket.h>

volatile sig_atomic_t terminate = 0;
volatile sig_atomic_t num_chld = 0;

void sigchld_handler(int s) {
    (void)s; // quiet unused variable warning
    // waitpid() might overwrite errno, so we save and restore it
    int saved_errno = errno;

    int status;
    pid_t pid;
    while((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        num_chld--;
        syslog(LOG_INFO, "Reaped child %d. Active connections %d", pid,  num_chld);
    }

    errno = saved_errno;
}

void sigterm_handler(int s) {
    (void)s; // quiet unused variable warning
    syslog(LOG_INFO, "Caught signal, exiting");
    terminate = 1;
}

void *get_in_addr(struct sockaddr *sa) {
    if(sa->sa_family == AF_INET)
        return &(((struct sockaddr_in *)sa)->sin_addr);
    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int main(int argc, char* argv[]) {
    int sock_fd, con_fd; // socket descriptors
    struct addrinfo hints, *p, *servinfo;
    struct sockaddr_storage con_addr;
    socklen_t con_addr_size;
    struct sigaction sa_chld, sa_term;
    int yes=1;
    char ipstr[INET6_ADDRSTRLEN];
    int status;

    // We will be using syslog to record troubleshooting messages instead of the
    // console. You can find those in /var/log/syslog (usually)
    openlog(NULL, 0, LOG_USER);

    memset(&hints, 0, sizeof hints); // make sure the struct is empty
    hints.ai_family = AF_INET; // don't care IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
    if((status = getaddrinfo(NULL, SERV_PORT, &hints, &servinfo)) != 0) {
        syslog(LOG_ERR, "getaddrinfo: %s\n", gai_strerror(status));
        return -1;
    }

    // Looking for valid address
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if((sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("serv: socket");
            continue;
        }

        if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("setsockopt");
            exit(-1);
        }

        if(bind(sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sock_fd);
            perror("server: bind");
            continue;
        }

        break;
    }
    freeaddrinfo(servinfo);
    if(p == NULL) {
        syslog(LOG_ERR, "server: failed to bind\n");    
        exit(-1);
    }

    // If all good and we can bind and the user wishes, daemonize yourself!
    if(argc > 1 && strcmp(argv[1], "-d") == 0)
        daemon(0, 0);


    if(listen(sock_fd, BACKLOG) == -1) {
        perror("listen");
        exit(-1);
    }

    // Reap all dead processes
    sa_chld.sa_handler = sigchld_handler;
    sigemptyset(&sa_chld.sa_mask);
    sa_chld.sa_flags = SA_RESTART;
    if(sigaction(SIGCHLD, &sa_chld, NULL) == -1) {
        perror("sigaction: sigchld");
        exit(-1);
    }

    // Gracefully terminate with SIGTERM or SIGINT
    sa_term.sa_handler = sigterm_handler;
    sigemptyset(&sa_term.sa_mask);
    sa_term.sa_flags = 0;
    if(sigaction(SIGTERM, &sa_term, NULL) == -1) {
        perror("sigaction: sigterm");
        exit(-1);
    }
    if(sigaction(SIGINT, &sa_term, NULL) == -1) {
        perror("sigaction: sigint");
        exit(-1);
    }

    syslog(LOG_INFO, "server: waiting for connections...");
    while(!terminate) {
        con_addr_size = sizeof con_addr;
        con_fd = accept(sock_fd, (struct sockaddr *)&con_addr, &con_addr_size);
        if(con_fd < 0) {
            if(errno == EINTR && terminate) 
                break;
            perror("accept");
            continue;
        }
        if(num_chld > MAX_CHLD) {
            syslog(LOG_ERR, "server: failed to accept. Maximum connections reaced.\n");    
            if(close(con_fd) == -1)
                perror("con fd: close");
            continue;
        }

        inet_ntop(
            con_addr.ss_family,
            get_in_addr((struct sockaddr *)&con_addr),
            ipstr,
            sizeof ipstr
        );
        syslog(LOG_INFO, "Accepted connection from  %s", ipstr);
        syslog(LOG_INFO, "Active connections %d", ++num_chld);

        pid_t pid = fork();
        if(pid == 0) {
            int exit_status = 0;
            int out_fd;
            struct packet_buf *pbuf = NULL, *prev_pbuf = NULL, *new_pbuf = NULL;
            char *recv_buf;
            int recv_bytes, write_bytes, read_bytes, sent_bytes;
            int total_recv_bytes, total_sent_bytes;
            int next_out_idx;

            // Inside the child. No need for connection listener
            close(sock_fd);

            // Output file
            out_fd = open(OUT_FILE, O_RDWR | O_CREAT | O_APPEND, 0644);
            if (out_fd == -1) {
                perror("outfile: open");
                _exit(-1);
            }
            // Receiving logic
            /*
             * Recive all data from client and make sure all delivered
             * successfully before writing to out file.
             */
            recv_buf = (char *)malloc(RECV_BUF_LEN);
            total_recv_bytes = 0;
            total_sent_bytes = 0;
            while((recv_bytes = recv(con_fd, recv_buf, RECV_BUF_LEN, 0)) > 0) {
                total_recv_bytes += recv_bytes;
                // Newline character marks the end of a packets and triggers writing to output file
                syslog(LOG_INFO, "Received %d bytes from %s", recv_bytes, ipstr);
                next_out_idx = 0;
                for(int idx = 0; idx < recv_bytes; idx++)
                    if(recv_buf[idx] == '\n') {
                        if(lseek(out_fd, 0, SEEK_END) == -1) {
                            perror("outfile: seek");
                            exit_status = -1;
                            goto cleanup;
                        }
                        while(pbuf != NULL) {
                            write_bytes = write(out_fd, pbuf->chars, pbuf->buf_len);
                            syslog(LOG_INFO, "wrote %d bytes from buffer to %s", write_bytes, OUT_FILE);
                            if(write_bytes == -1) {
                                perror("outfile: write");
                                exit_status = -1;
                                goto cleanup;
                            }
                            prev_pbuf = pbuf;
                            pbuf = pbuf->next_buf;
                            free(prev_pbuf);
                        }
                        write_bytes = write(out_fd, recv_buf, idx - next_out_idx + 1);
                        syslog(LOG_INFO, "wrote %d bytes from recv buffer to %s", write_bytes, OUT_FILE);
                        if(write_bytes == -1) {
                            perror("outfile: write");
                            exit_status = -1;
                            goto cleanup;
                        }
                        next_out_idx = idx + 1;

                        // Sending back to client. Start from the beginning of the file
                        if(lseek(out_fd, 0, SEEK_SET) == -1) {
                            perror("outfile: seek");
                            exit_status = -1;
                            goto cleanup;
                        }
                        while((read_bytes = read(out_fd, recv_buf, RECV_BUF_LEN)) != 0) {
                            syslog(LOG_INFO, "read %d bytes from %s", read_bytes, OUT_FILE);
                            if(read_bytes == -1) {
                                if(errno == EINTR)
                                    continue;
                                perror("out file: read");
                                exit_status = -1;
                                goto cleanup;
                            }
                            if((sent_bytes = send(con_fd, recv_buf, read_bytes, 0)) == -1) {
                                perror("server: send");
                                exit_status = -1;
                                goto cleanup;
                            }
                            total_sent_bytes += read_bytes;
                            syslog(LOG_INFO, "Sent %d bytes to %s", sent_bytes, ipstr);
                        }
                    }
                if(next_out_idx < recv_bytes) {
                    new_pbuf = (struct packet_buf *)malloc(sizeof(struct packet_buf));
                    new_pbuf->chars = (char *)malloc(recv_bytes - next_out_idx);
                    new_pbuf->next_buf = NULL;
                    memmove(new_pbuf->chars, recv_buf, recv_bytes - next_out_idx);
                    new_pbuf->buf_len = recv_bytes - next_out_idx;
                    if(pbuf == NULL)
                        pbuf = new_pbuf;
                    else {
                        prev_pbuf = pbuf;
                        while(prev_pbuf->next_buf != NULL)
                            prev_pbuf = prev_pbuf->next_buf;
                        prev_pbuf->next_buf = new_pbuf;
                    }
                    syslog(LOG_INFO, "saved %d bytes to buffer", recv_bytes - next_out_idx);
                }
            }
            if(recv_bytes < 0) {
                perror("recv: ");
                exit_status = -1;
                goto cleanup;
            }
            syslog(LOG_INFO, "Total %s - received: %d, sent: %d ", ipstr, total_recv_bytes, total_sent_bytes);
// Freeing all acquired resources. We don't faile on error in any
// particular step to give ourselves a chance to free the rest.
cleanup:
            free(recv_buf);
            while(pbuf != NULL) {
                prev_pbuf = pbuf;
                pbuf = pbuf->next_buf;
                free(prev_pbuf);
            }
            if(close(out_fd) == -1)
                perror("outfile: close");
            if(close(con_fd) == -1)
                perror("con fd: close");
            else
                syslog(LOG_INFO, "Closed connection from  %s", ipstr);
            _exit(exit_status);
        }
        else if(pid < 0) {
            perror("fork");
            continue;
        }
        // Inside parent. No need for open conenction
        close(con_fd);
    }
    syslog(LOG_INFO, "server: shutting down gracefully...");
    /*
     * Gracefully exits when SIGINT or SIGTERM is received.
     * Completing any open connection operations
     * Closing any open sockets
     * Deleting the file /var/tmp/aesdsocketdata
    */
    // SIGCHLD handler reaps each individual child when it terminates. This
    // lines waites for all of them to do.
    while(!(waitpid(-1, NULL, 0) == -1 && errno == ECHILD));
    syslog(LOG_INFO, "server: all connections closed");

    if(remove(OUT_FILE) == -1)
        perror("outfile: remove");
    syslog(LOG_INFO, "server: %s removed", OUT_FILE);

    syslog(LOG_INFO, "Server exited successfully.");

    return 0;
}
