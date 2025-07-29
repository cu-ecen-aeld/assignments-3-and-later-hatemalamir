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
#include <sys/socket.h>
#include <sys/epoll.h>
#include <time.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#include "uthash.h"
#include "aesdsocket.h"

static volatile sig_atomic_t terminate = 0;

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

int append_to_pbuf(char *chars, int len, struct packet **head, struct packet **tail) {
    struct packet *new_pbuf = (struct packet *)malloc(sizeof(struct packet));
    if(!new_pbuf) {
        perror("malloc: append_to_pbuf: new_pbuf");
        return -1;
    }
    new_pbuf->chars = (char *)malloc(len);
    if(!new_pbuf->chars) {
        perror("malloc: append_to_pbuf: new_pbuf->chars");
        free(new_pbuf);
        return -1;
    }
    memmove(new_pbuf->chars, chars, len);
    new_pbuf->len = len;
    new_pbuf->next = NULL;
    if(*head == NULL) {
        *head = new_pbuf;
        *tail = new_pbuf;
    }
    else {
        (*tail)->next = new_pbuf;
        *tail = new_pbuf;
    }

    return 0;
}

void free_pbuf(struct packet *pbuf_head) {
    struct packet *temp;
    while(pbuf_head != NULL) {
        temp = pbuf_head->next;
        free(pbuf_head->chars);
        free(pbuf_head);
        pbuf_head = temp;
    }
}

void* con_read(void *th_args) {
    struct con_read_args *args = (struct con_read_args *)th_args;
    int recv_bytes=0, total_recv_bytes=0, recv_packet_len = 0, idx;
    struct packet *pbuf_head = NULL, *pbuf_tail = NULL;
    char *con_buf = (char *)malloc(CON_BUF_LEN);
    if(!con_buf) {
        perror("malloc: con_buf: con_read");
        goto cleanup;
    }
    while((recv_bytes = recv(args->con_fd, con_buf, CON_BUF_LEN, 0)) > 0) {
        syslog(LOG_INFO, "sock fd: %d, received %d bytes.", args->con_fd, recv_bytes);
        total_recv_bytes += recv_bytes;
        /*
         * Packet ends with '\n'. If found, write to recv_buf.
         * Start from the end to handle the unlikely case of multipl packets in the same connection.
       */
        for(idx = recv_bytes - 1; idx >= 0; idx--)
            if(con_buf[idx] == '\n') {
                if(append_to_pbuf(con_buf, idx + 1, &pbuf_head, &pbuf_tail) != 0)
                    goto cleanup;
                recv_packet_len += (idx + 1);
                struct con_l_elem *disk_q_elem = (struct con_l_elem*)malloc(sizeof(struct con_l_elem));
                if(!disk_q_elem) {
                    perror("malloc: disk_q_elem");
                    goto cleanup;
                }
                disk_q_elem->con_fd = args->con_fd;
                disk_q_elem->next = NULL;
                pthread_mutex_lock(&(args->recv_buf->lock));
                if(args->recv_buf->head == NULL)
                    args->recv_buf->head = pbuf_head;
                else
                    args->recv_buf->tail->next = pbuf_head;
                args->recv_buf->tail = pbuf_tail;
                pthread_mutex_unlock(&(args->recv_buf->lock));
                // Clear local references so that we don't delete after adding to shared recv_buf.
                pbuf_head = NULL;
                pbuf_tail = NULL;
                syslog(LOG_INFO, "sock fd: %d, total packet lenght: %d, total recv bytes: %d.", args->con_fd, recv_packet_len, total_recv_bytes);
                // Move con_fd to disk_q
                pthread_mutex_lock(&(args->disk_q->lock));
                if(args->disk_q->head == NULL) {
                    args->disk_q->head = disk_q_elem;
                    args->disk_q->tail = disk_q_elem;
                }
                else {
                    args->disk_q->tail->next = disk_q_elem;
                    args->disk_q->tail = disk_q_elem;
                }
                pthread_mutex_unlock(&(args->disk_q->lock));
                uint64_t set = 1;
                write(args->outf_eid, &set, sizeof(set));
                goto cleanup;
            }
        if(idx < 0) {
            if(append_to_pbuf(con_buf, recv_bytes, &pbuf_head, &pbuf_tail) != 0)
                goto cleanup;
            recv_packet_len += recv_bytes;
        }
    }
    if(recv_bytes < 0) {
        perror("recv: ");
        // If con errs in sending, rest is pointless.
        if(epoll_ctl(args->epfd, EPOLL_CTL_DEL, args->con_fd, NULL))
            perror("epoll_ctl: del");
        close(args->con_fd);
        pthread_mutex_lock(&(args->con_ctr->lock));
        args->con_ctr->num_con--;
        pthread_mutex_unlock(&(args->con_ctr->lock));
        syslog(LOG_INFO, "sock fd: %d, connection closed due to error. Active connections: %d", args->con_fd, args->con_ctr->num_con);
    }
cleanup:
    if(con_buf)
        free(con_buf);
    free_pbuf(pbuf_head);
    args->thctl->done = 1;
    free(th_args);

    return NULL;
}

void* write_to_disk(void *th_args) {
    struct write_to_disk_args *args = (struct write_to_disk_args *)th_args;
    pthread_mutex_lock(&(args->out_fctl->lock));
    pthread_mutex_lock(&(args->recv_buf->lock));
    pthread_mutex_lock(&(args->disk_q->lock));
    if(lseek(args->out_fctl->fd, 0, SEEK_END) == -1) {
        perror("outfile: seek: write_to_disk");
        goto cleanup;
    }
    int write_bytes, total_write_bytes=0;
    struct packet *next_packet;
    while(args->recv_buf->head != NULL) {
        write_bytes = write(args->out_fctl->fd, args->recv_buf->head->chars, args->recv_buf->head->len);
        if(write_bytes == -1) {
            perror("outfile: write");
            goto cleanup;
        }
        total_write_bytes += write_bytes;
        next_packet = args->recv_buf->head->next;
        free(args->recv_buf->head->chars);
        free(args->recv_buf->head);
        args->recv_buf->head = next_packet;
    }
    syslog(LOG_INFO, "Wrote %d bytes to %s", total_write_bytes, OUT_FILE);

    struct con_l_elem *next_elem;
    while(args->disk_q->head != NULL) {
        struct con_hash *con_h = (struct con_hash *)malloc(sizeof(struct con_hash));
        if(con_h != NULL) {
            int con_fd = args->disk_q->head->con_fd;
            con_h->con_fd = con_fd;
            HASH_ADD_INT(*(args->send_q), con_fd, con_h);
            syslog(LOG_INFO, "sock fd: %d, pending server response.", con_fd);
        }
        else {
            perror("malloc: con_hash: write_to_disk");
            /*
             * It might look a bit extreme to close the connection if a malloc
             * error occured which is no fault of the connection itself and we
             * could leave it in the queue and retry later. Although, I chose
             * thisbecause it's simpler, and if the server is actually
             * struggling with memory that would relieve some of the stress.
             */
            if(epoll_ctl(args->epfd, EPOLL_CTL_DEL, args->disk_q->head->con_fd, NULL))
                perror("epoll_ctl: del: write_to_disk");
            close(args->disk_q->head->con_fd);
            pthread_mutex_lock(&(args->con_ctr->lock));
            args->con_ctr->num_con--;
            pthread_mutex_unlock(&(args->con_ctr->lock));
            syslog(LOG_INFO, "sock fd: %d, connection closed due to error. Active connections: %d", args->disk_q->head->con_fd, args->con_ctr->num_con);
        }
        next_elem = args->disk_q->head->next;
        free(args->disk_q->head);
        args->disk_q->head = next_elem;
    }
    args->disk_q->tail = NULL;
cleanup:
    if(args->recv_buf->head == NULL)
        args->recv_buf->tail = NULL;
    pthread_mutex_unlock(&(args->disk_q->lock));
    pthread_mutex_unlock(&(args->recv_buf->lock));
    pthread_mutex_unlock(&(args->out_fctl->lock));
    args->thctl->done = 1;
    free(th_args);

    return NULL;
}

void* con_write(void *th_args) {
    struct con_write_args *args = (struct con_write_args *)th_args;
    char *con_buf = (char *)malloc(CON_BUF_LEN);
    if(!con_buf) {
        perror("malloc: con_buf: con_write");
        goto cleanup;
    }
    pthread_mutex_lock(&(args->out_fctl->lock));
    if(lseek(args->out_fctl->fd, 0, SEEK_SET) == -1) {
        perror("outfile: seek: con_write");
        goto cleanup;
    }
    int  read_bytes, sent_bytes, total_sent_bytes=0;
    while((read_bytes = read(args->out_fctl->fd, con_buf, CON_BUF_LEN)) != 0) {
        syslog(LOG_INFO, "sock fd: %d, read %d bytes from %s", args->con_fd, read_bytes, OUT_FILE);
        if(read_bytes == -1) {
            if(errno == EINTR)
                continue;
            perror("out file: read: con_write");
            goto cleanup;
        }
        if((sent_bytes = send(args->con_fd, con_buf, read_bytes, 0)) == -1) {
            perror("send");
            goto cleanup;
        }
        total_sent_bytes += read_bytes;
        syslog(LOG_INFO, "sock fd: %d, sent %d bytes", args->con_fd, sent_bytes);
    }
    syslog(LOG_INFO, "sock fd: %d, total sent bytes: %d", args->con_fd, total_sent_bytes);
cleanup:
    pthread_mutex_unlock(&(args->out_fctl->lock));
    if(epoll_ctl(args->epfd, EPOLL_CTL_DEL, args->con_fd, NULL))
        perror("epoll_ctl: del: con_send");
    close(args->con_fd);
    pthread_mutex_lock(&(args->con_ctr->lock));
    args->con_ctr->num_con--;
    pthread_mutex_unlock(&(args->con_ctr->lock));
    syslog(LOG_INFO, "sock fd: %d, connection closed. Active connections: %d", args->con_fd, args->con_ctr->num_con);
    if(con_buf)
        free(con_buf);
    args->thctl->done = 1;
    free(th_args);

    return NULL;
}

void add_thread(struct thread_ctl *threads, struct thread_ctl_elem *th) {
    if(threads->head == NULL)
        threads->head = th;
    else {
        struct thread_ctl_elem *tail = threads->head;
        while(tail->next != NULL)
            tail = tail->next;
        tail->next = th;
    }
    (threads->threadc)++;
    syslog(LOG_INFO, "Thread %lu added. Active threads: %d", th->threadh, threads->threadc);
}

void clean_con_q(struct con_hash *q) {
    struct con_hash *cur, *tmp;
    HASH_ITER(hh, q, cur, tmp) {
        close(cur->con_fd);
        HASH_DEL(q, cur);
        free(cur);
    }
}

void* write_time(void *th_args) {
    struct write_time_args *args = (struct write_time_args *)th_args;
    char outstr[64];
    time_t t;
    struct tm *tmp;

    pthread_mutex_lock(&(args->out_fctl->lock));
    t = time(NULL);
    tmp = localtime(&t);
    if(tmp == NULL) {
        perror("localtime");
        goto cleanup;
    }
    int len;
    if((len = strftime(&(outstr[0]), sizeof(outstr), "timestamp:%a, %d %b %Y %T %z%n", tmp)) == 0) {
        syslog(LOG_INFO, "Error! strftime returned 0. Possibly formatted string longer than buffer.");
        goto cleanup;
    }
    if(lseek(args->out_fctl->fd, 0, SEEK_END) == -1) {
        perror("outfile: seek: alarm_handler");
        goto cleanup;
    }
    int write_bytes;
    write_bytes = write(args->out_fctl->fd, outstr, len);
    if(write_bytes == -1) {
        perror("outfile: write: alarm_handler");
        goto cleanup;
    }
    syslog(LOG_INFO, "Wrote %d time bytes to %s", write_bytes, OUT_FILE);
cleanup:
    pthread_mutex_unlock(&(args->out_fctl->lock));
    args->thctl->done = 1;
    free(th_args);

    return NULL;
}

int main(int argc, char* argv[]) {
    // We will be using syslog to record troubleshooting messages instead of the
    // console. You can find those in /var/log/syslog (usually)
    openlog(NULL, 0, LOG_USER);

    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    if(nproc < 1) {
        perror("sysconf: nproc");
        exit(-1);
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof hints); // make sure the struct is empty
    hints.ai_family = AF_INET; // don't care IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
    int status;
    struct addrinfo *servinfo;
    if((status = getaddrinfo("0.0.0.0", SERV_PORT, &hints, &servinfo)) != 0) {
        syslog(LOG_ERR, "getaddrinfo: %s\n", gai_strerror(status));
        return -1;
    }

    int sock_fd; // socket descriptors
    // Looking for valid address
    struct addrinfo *p;
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if((sock_fd = socket(p->ai_family, p->ai_socktype | SOCK_NONBLOCK, p->ai_protocol)) == -1) {
            perror("serv: socket");
            continue;
        }

        int yes=1;
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

    // Gracefully terminate with SIGTERM or SIGINT
    struct sigaction sa_term;
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

    struct con_hash *recv_q=NULL, *send_q=NULL;
    // Connections waited their packets to be written to disk
    struct con_l disk_q;
    disk_q.head = NULL;
    disk_q.tail = NULL;
    if(pthread_mutex_init(&(disk_q.lock), NULL) != 0) {
        perror("pthread_mutex_init: disk_q");
        exit(-1);
    }
    // Shared buffer of all received packets until they're written to disk
    struct rw_buf recv_buf;
    recv_buf.head = NULL;
    recv_buf.tail = NULL;
    if(pthread_mutex_init(&(recv_buf.lock), NULL) != 0) {
        perror("pthread_mutex_init: recv_buf");
        exit(-1);
    }
    // Main event monitoring handler
    int epfd = epoll_create1(0);
    if(epfd < 0) {
        perror("epoll_create1");
        exit(-1);
    }
    // Time tracker
    int tfd = timerfd_create(CLOCK_REALTIME, 0);
    if(tfd == -1) {
        perror("timerfd_create");
        exit(-1);
    }
    struct itimerspec its;
    its.it_value.tv_sec = 10;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 10;
    its.it_interval.tv_nsec = 0;
    if(timerfd_settime(tfd, 0, &its, NULL) == -1) {
        perror("timerfd_settime");
        exit(-1);
    }
    // Connection counter
    struct num_con_ctl con_ctr;
    if(pthread_mutex_init(&(con_ctr.lock), NULL) != 0) {
        perror("pthread_mutex_init: num_con_ctl");
        exit(-1);
    }
    con_ctr.num_con = 0;
    // Output file
    struct file_ctl out_fctl;
    if(pthread_mutex_init(&(out_fctl.lock), NULL) != 0) {
        perror("pthread_mutex_init: out_fctl");
        exit(-1);
    }
    out_fctl.fd = open(OUT_FILE, O_RDWR | O_CREAT | O_APPEND, 0644);
    if (out_fctl.fd == -1) {
        perror("open: out_fctl");
        exit(-1);
    }
    int outf_eid = eventfd(0, 0);
    if(outf_eid == -1) {
        perror("eventfd");
        exit(-1);
    }

    int exit_status = 0;
    struct epoll_event *serv_events=NULL;
    // All monitored events
    serv_events = malloc(sizeof(struct epoll_event) * MAX_EPOLL_EVENTS);
    if(!serv_events) {
        perror("malloc: serv_events");
        exit_status = -1;
        goto cleanup;
    }
    // Monitor server socket
    struct epoll_event sock_event;
    sock_event.data.fd = sock_fd;
    sock_event.events = EPOLLIN;
    if(epoll_ctl(epfd, EPOLL_CTL_ADD, sock_fd, &sock_event) < 0) {
        perror("epoll_ctl: sock_fd");
        exit_status = -1;
        goto cleanup;
    }
    // Monitor output file
    struct epoll_event outf_event;
    outf_event.data.fd = outf_eid;
    outf_event.events = EPOLLIN;
    if(epoll_ctl(epfd, EPOLL_CTL_ADD, outf_eid, &outf_event) < 0) {
        perror("epoll_ctl: outf_eid");
        exit_status = -1;
        goto cleanup;
    }
    // Track time
    struct epoll_event time_event;
    time_event.data.fd = tfd;
    time_event.events = EPOLLIN;
    if(epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &time_event) < 0) {
        perror("epoll_ctl: tfd");
        exit_status = -1;
        goto cleanup;
    }

    int nr_events; 
    struct sockaddr_storage con_addr;
    socklen_t con_addr_size = sizeof con_addr;
    char ipstr[INET6_ADDRSTRLEN];
    // Thread tracking
    struct thread_ctl threads;
    threads.head = NULL;
    threads.threadc = 0;
    struct thread_ctl_elem *cur_th, *prev_th, *del_th;

    syslog(LOG_INFO, "server: waiting for connections...");
    while(!terminate || con_ctr.num_con > 0) {
        nr_events = epoll_wait(epfd, serv_events, MAX_EPOLL_EVENTS, 1000);
        if(nr_events < 0 && errno != EINTR) {
            perror("epoll_wait");
            goto cleanup;
        }
        for(int i=0; i < nr_events; i++) {
            if(!terminate && serv_events[i].data.fd == sock_fd) {
                int con_fd; // socket descriptors
                // In case multiple clients try to connect since we last waited
                while((con_fd = accept(sock_fd, (struct sockaddr *)&con_addr, &con_addr_size)) != -1) {
                    struct con_hash *con_h = (struct con_hash *)malloc(sizeof(struct con_hash));
                    if(!con_h) {
                        perror("malloc: con_hash: main");
                        close(con_fd);
                        continue;
                    }
                    con_h->con_fd = con_fd;
                    HASH_ADD_INT(recv_q, con_fd, con_h);
                    // Dynamically allocated so that it doesn't go out of scope
                    struct epoll_event con_event;
                    con_event.data.fd = con_fd;
                    con_event.events = EPOLLIN | EPOLLOUT;
                    if(epoll_ctl(epfd, EPOLL_CTL_ADD, con_fd, &con_event) < 0) {
                        perror("epoll_ctl: con_fd");
                        close(con_fd);
                        free(con_h);
                        continue;
                    }
                    inet_ntop(
                        con_addr.ss_family,
                        get_in_addr((struct sockaddr *)&con_addr),
                        ipstr,
                        sizeof ipstr
                    );
                    pthread_mutex_lock(&(con_ctr.lock));
                    con_ctr.num_con++;
                    pthread_mutex_unlock(&(con_ctr.lock));
                    syslog(LOG_INFO, "Accepted connection from: %s, sock fd: %d, active connections: %d.", ipstr, con_fd, con_ctr.num_con);
                }
                if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
                    perror("accept");
            }
            if(serv_events[i].data.fd == outf_eid && threads.threadc < nproc) {
                // Clear the event
                uint64_t clear = 1;
                read(outf_eid, &clear, sizeof(clear));
                struct write_to_disk_args *args = (struct write_to_disk_args*)malloc(sizeof(struct write_to_disk_args));
                if(!args) {
                    perror("malloc: write_to_disk_args");
                    continue;
                }
                args->recv_buf = &recv_buf;
                args->out_fctl = &out_fctl;
                args->disk_q = &disk_q;
                args->send_q = &send_q;
                args->epfd = epfd;
                args->con_ctr = &con_ctr;
                struct thread_ctl_elem *th = (struct thread_ctl_elem *)malloc(sizeof(struct thread_ctl_elem));
                if(!th) {
                    perror("malloc: thrad_ctl_elem: write_to_disk");
                    free(args);
                    continue;
                }
                th->done = 0;
                th->next = NULL;
                args->thctl = th;
                if(pthread_create(&(th->threadh), NULL, write_to_disk, args) != 0) {
                    perror("pthread_create: write_to_disk");
                    free(args);
                    free(th);
                }
                else
                    add_thread(&threads, th);
            }
            if(serv_events[i].data.fd == tfd && threads.threadc < nproc) {
                // Clear the event
                uint64_t clear = 1;
                read(tfd, &clear, sizeof(clear));
                struct write_time_args *args = (struct write_time_args*)malloc(sizeof(struct write_to_disk_args));
                if(!args) {
                    perror("malloc: write_args");
                    continue;
                }
                args->out_fctl = &out_fctl;
                struct thread_ctl_elem *th = (struct thread_ctl_elem *)malloc(sizeof(struct thread_ctl_elem));
                if(!th) {
                    perror("malloc: thrad_ctl_elem: write_time");
                    free(args);
                    continue;
                }
                th->done = 0;
                th->next = NULL;
                args->thctl = th;
                if(pthread_create(&(th->threadh), NULL, write_time, args) != 0) {
                    perror("pthread_create: write_time");
                    free(args);
                    free(th);
                }
                else
                    add_thread(&threads, th);
            }
            else {
                struct con_hash * con_h;
                HASH_FIND_INT(recv_q, &(serv_events[i].data.fd) , con_h);
                if(con_h && (serv_events[i].events & EPOLLIN) && threads.threadc < nproc) {
                    syslog(LOG_INFO, "sock fd: %d, ready for receivng data from client", serv_events[i].data.fd);
                    struct con_read_args *args = (struct con_read_args*)malloc(sizeof(struct con_read_args));
                    if(!args) {
                        perror("malloc: con_read_args");
                        continue;
                    }
                    args->con_fd = serv_events[i].data.fd;
                    args->recv_buf = &recv_buf;
                    args->disk_q = &disk_q;
                    args->outf_eid = outf_eid;
                    args->epfd = epfd;
                    args->con_ctr = &con_ctr;
                    struct thread_ctl_elem *th = (struct thread_ctl_elem *)malloc(sizeof(struct thread_ctl_elem));
                    if(!th) {
                        perror("malloc: thrad_ctl_elem: con_read");
                        free(args);
                        continue;
                    }
                    th->done = 0;
                    th->next = NULL;
                    args->thctl = th;
                    if(pthread_create(&(th->threadh), NULL, con_read, args) != 0) {
                        perror("pthread_create: con_read");
                        free(args);
                        free(th);
                        continue;
                    }
                    else
                        add_thread(&threads, th);
                    HASH_DEL(recv_q, con_h);
                    free(con_h);
                    // We don't need to check send_q if con_fd was found in recv_q
                    continue;
                }
                HASH_FIND_INT(send_q, &(serv_events[i].data.fd) , con_h);
                if(con_h && (serv_events[i].events & EPOLLOUT) && threads.threadc < nproc) {
                    syslog(LOG_INFO, "sock fd: %d, ready for sending data to client", serv_events[i].data.fd);
                    struct con_write_args *args = (struct con_write_args*)malloc(sizeof(struct con_write_args));
                    if(!args) {
                        perror("malloc: con_write_args");
                        continue;
                    }
                    args->con_fd = serv_events[i].data.fd;
                    args->out_fctl = &out_fctl;
                    args->epfd = epfd;
                    args->con_ctr = &con_ctr;
                    struct thread_ctl_elem *th = (struct thread_ctl_elem *)malloc(sizeof(struct thread_ctl_elem));
                    if(!th) {
                        perror("malloc: thrad_ctl_elem: con_write");
                        free(args);
                        continue;
                    }
                    th->done = 0;
                    th->next = NULL;
                    args->thctl = th;
                    if(pthread_create(&(th->threadh), NULL, con_write, args) != 0) {
                        perror("pthread_create: con_write");
                        free(args);
                        free(th);
                        continue;
                    }
                    else
                        add_thread(&threads, th);
                    HASH_DEL(send_q, con_h);
                    free(con_h);
                }
            }
        }
        /* Garbage-collect finished threads. The implementation is a bit verbose
         * but, hopefully, less confusing.*/
        cur_th = threads.head;
        prev_th = threads.head;
        while(cur_th != NULL) {
            if(threads.threadc <= 0) {
                syslog(LOG_INFO, "ERROR! Thread garbage collector. Thread list out of boundary!");
                goto shutdown;
            }
            if(cur_th->done) {
                pthread_join(cur_th->threadh, NULL);
                del_th = cur_th;
                if(cur_th == threads.head) {
                    threads.head = threads.head->next;
                    cur_th = threads.head;
                    prev_th = threads.head;
                }
                else {
                    prev_th->next = cur_th->next;
                    cur_th = prev_th->next;
                }
                pthread_t del_th_id = del_th->threadh;
                free(del_th);
                threads.threadc--;
                syslog(LOG_INFO, "Thread %lu removed. Active threads: %d", del_th_id, threads.threadc);
            }
            else {
                prev_th = cur_th;
                cur_th = cur_th->next;
            }
        }
    }
cleanup:
    /*
     * Gracefully exits when SIGINT or SIGTERM is received.
     * Completing any open connection operations
     * Closing any open sockets
     * Deleting the file /var/tmp/aesdsocketdata
    */
    syslog(LOG_INFO, "server: shutting down gracefully...");
    cur_th = threads.head;
    struct thread_ctl_elem *del_elem;
    while(cur_th != NULL) {
        pthread_join(cur_th->threadh, NULL);
        del_elem = cur_th;
        cur_th = cur_th->next;
        free(del_elem);
        threads.threadc--;
    }
shutdown:
    clean_con_q(recv_q);
    if(disk_q.head) {
        struct con_l_elem *temp;
        struct con_l_elem *del_elem = disk_q.head;
        while(del_elem != NULL) {
            close(del_elem->con_fd);
            temp = del_elem->next;
            free(del_elem);
            del_elem = temp;
        }
    }
    clean_con_q(send_q);
    syslog(LOG_INFO, "server: all connections closed");
    close(epfd);
    close(sock_fd);
    close(tfd);
    close(outf_eid);
    // Free dynamic memory
    if(serv_events)
        free(serv_events);
    free_pbuf(recv_buf.head);

    if(out_fctl.fd) {
        if(remove(OUT_FILE) == -1)
            perror("outfile: remove");
        syslog(LOG_INFO, "server: %s removed", OUT_FILE);
    }

    if(exit_status == 0)
        syslog(LOG_INFO, "Server exited successfully.");
    else
        syslog(LOG_INFO, "Server exited with ERROR!");

    closelog();
    return exit_status;
}
