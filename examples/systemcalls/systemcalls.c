#define _XOPEN_SOURCE
#include "systemcalls.h"
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>

/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{

/*
 * TODO  add your code here
 *  Call the system() function with the command set in the cmd
 *   and return a boolean true if the system() call completed with success
 *   or false() if it returned a failure
*/
    int ret;
    ret = system(cmd);
    if(!WIFEXITED(ret))
        return false;
    if(WEXITSTATUS(ret) != 0)
        return false;

    return true;
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    command[count] = command[count];

/*
 * TODO:
 *   Execute a system command by calling fork, execv(),
 *   and wait instead of system (see LSP page 161).
 *   Use the command[0] as the full path to the command to execute
 *   (first argument to execv), and use the remaining arguments
 *   as second argument to the execv() command.
 *
*/
    int status;
    pid_t pid;

    fflush(stdout);
    pid = fork();
    if(pid == -1)
        return false;
    else if(pid == 0) {
        // child
        execv(command[0], command);
        // If you get to this line, exev has failed already!
        perror("> execv");
        printf("> Child - execv failed to execute %s\n", command[0]);
        _exit(-1);
    }
    // If there is an error in calling waitpid()
    if(waitpid(pid, &status, 0) == -1){
        perror("> waitpid");
        return false;
    }
    // If process exitted normally
    else if(WIFEXITED(status)) {
        int st = WEXITSTATUS(status); 
        if(st != 0) {
            printf("> Parent - WEXITSTATUS: %d\n", st);
            return false;
        }
    }
    // If process did not exit normally (interrupted, etc)
    else {
        printf("> Parent - Child did not exit normally!\n");
        return false;
    }

    va_end(args);

    return true;
}

/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    command[count] = command[count];


/*
 * TODO
 *   Call execv, but first using https://stackoverflow.com/a/13784315/1446624 as a refernce,
 *   redirect standard out to a file specified by outputfile.
 *   The rest of the behaviour is same as do_exec()
 *
*/
    // Making sure the output file is accessible and writable.
    int fd = open(outputfile, O_WRONLY | O_TRUNC | O_CREAT, 0644);
    if(fd < 0) {
        perror(">> open");
        return false;
    }

    // Creating the child process that will do the writing.
    int cid;
    int status;
    fflush(stdout);
    switch(cid = fork()) {
        case -1:
            perror(">> fork");
            return false;
        case 0:
            /*
             * Copies the open file descriptor into standard output, which means
             * anything you write to standard output from this process will go
             * to the specified file.
            */
            if(dup2(fd, 1) < 0) {
                perror(">> dup2");
                return false;
            }
            /*
             * Remember, standard output referes to the same file now so we
             * don't need this one.
            */
            close(fd);
            // Now it's time to rock!
            execv(command[0], command);
            perror(">> execv");
            printf(">> Child - execv failed to execute %s\n", command[0]);
            _exit(-1);
        default:
            // And life goes on for the parent...
            // If there is an error in calling waitpid()
            if(waitpid(cid, &status, 0) == -1) {
                perror(">> waitpid");
                return false;
            }
            // If process exitted normally
            else if(WIFEXITED(status)) {
                int st = WEXITSTATUS(status);
                if(st != 0) {
                    printf(">> Parent - WEXITSTATUS: %d\n", st);
                    return false;
                }
            }
            else {
                printf(">> Parent - Child did not exit normally!\n");
                return false;
            }
    }

    va_end(args);

    return true;
}
