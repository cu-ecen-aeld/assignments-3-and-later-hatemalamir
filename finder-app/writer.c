#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>

int main(int argc, char *argv[]) {
    // We will be using syslog to record troubleshooting messages instead of the
    // console. You can find those in /var/log/syslog (usually)
    openlog(NULL, 0, LOG_USER);

    // Not enough arguments
    if(argc < 3) {
        syslog(LOG_ERR, "MISSING ARGUMENTS!Usage: %s <output file path> <what to write to file>", argv[0]);
        return 1;
    }

    // Openning the file
    int fd;
    fd = open(argv[1], O_RDWR | O_CREAT | O_TRUNC, 0644);
    // Handle any openning errors
    if (fd == -1) {
        syslog(LOG_ERR, "Failed to open file %s.", argv[1]);
        return 1;
    }

    // Writing argument message
    syslog(LOG_DEBUG, "Writing %s to %s", argv[2], argv[1]);
    ssize_t nr;
    nr = write(fd, argv[2], strlen(argv[2]));
    if(nr == -1) {
        perror("Failed to write to file.");
        return 1;
    }
    syslog(LOG_DEBUG, "%ld bytes were successfully written to %s", nr, argv[1]);

    // Closing file
    if(close(fd) == -1)
        perror("Failed to close file.");
    syslog(LOG_DEBUG, "File closed successfully, %s", argv[1]);

    return 0;
}
