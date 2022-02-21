/*
 * AndrewId: enhanc
 */

/*
 * tsh - A tiny shell program with job control. The shell support built-in
 * command: quit, jobs, bg and fg. Built-in commands are run in the shell's
 * process. The shell also runs other excutables like /bin/ls. Command lines
 * ending with & are run as background jobs, else commands are run in the 
 * foreground. The shell maintains a job list that records the status of 
 * all running and stopped job. When a job finishes excution, the shell reaps
 * it and remove the entry in job list. The shell handles Ctrl-C and Ctrl-Z to 
 * terminate or stop child process. 
 * 
 * The code are built upon sample code snippets from CSAPP textbook chapter 8.
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <sys/wait.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);

int builtin_command(struct cmdline_tokens token);
void wait_fg_job(jid_t job, sigset_t *set);
void print_bg_jobs(struct cmdline_tokens token);
void change_job_state(char *ptr, bool is_fg);

typedef enum arg_state 
{
    ARG_JID,
    ARG_PID,
    ARG_EMPTY,
    ARG_INVALID

} arg_state;

arg_state parse_argument(char *ptr);

/*
 * Read and evaluate each line of command. Perform setup works including 
 * initialize the job list, install signal handler, and preprocess command
 * line. 
 * 
 * argc: input arguments counts
 * argv: pointer to arguments
 * 
 * Error conditions: This function prints out errors and exits if stderr 
 * redirection fails, putenv fails, setvbuf fails, or fgets fails.
 */
int main(int argc, char **argv) {
    char c;
    char cmdline[MAXLINE_TSH];  // Cmdline for fgets
    bool emit_prompt = true;    // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h':                   // Prints help message
            usage();
            break;
        case 'v':                   // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p':                   // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv("MY_ENV=42") < 0) {
        perror("putenv");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT,  sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler);  // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler);  // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

/*
 * Interpret and execute command line. If command is built-in, run within the
 * shell process. Otherwise, start a child process to run the job. Wait for 
 * foreground job to finish or return immediately if job is background. Signals
 * are blocked to prevent race condition when accessing job list.
 * 
 * cmdline: pointer to command line
 * 
 * Error conditions: This function will print out error if either file opening 
 * fails, or if the command is not found.
 */
void eval(const char *cmdline) {

    parseline_return parse_result;
    struct cmdline_tokens token;
    sigset_t mask_one, prev_one, mask_all;
    
    sigemptyset(&mask_one);
    sigfillset(&mask_all);
    sigaddset(&mask_one, SIGCHLD);
    int out_file = -1;
    int in_file = -1;
    
    int save_stdout = dup(STDOUT_FILENO);
    int save_stdin = dup(STDIN_FILENO);
    // Parse command line
    parse_result = parseline(cmdline, &token);

    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }

    if (!builtin_command(token)) {
        
       if (token.infile != NULL) {
            in_file = open(token.infile, O_RDONLY, S_IRUSR| S_IWUSR | S_IRGRP|S_IROTH);
            
            // open() error
            if (in_file < 0) {
                if (errno == ENOENT) {
                    sio_printf("%s: No such file or directory\n", token.infile);
                    return;
                }
                if (errno == EACCES) {
                    sio_printf("%s: Permission denied\n", token.infile);
                    return;
                }
            }

            dup2(in_file, STDIN_FILENO);
        }

        // open() error
        if (token.outfile != NULL) {
            out_file = open(token.outfile,O_CREAT|O_RDWR|O_TRUNC , 
                                S_IRUSR|S_IWUSR | S_IRGRP|S_IROTH );

            if(out_file < 0) {
               if (errno == EACCES) {
                    sio_printf("%s: Permission denied\n", token.outfile);
                    return;
                }
            }
            dup2(out_file, STDOUT_FILENO);
        }
        pid_t pid;
        sigprocmask(SIG_BLOCK, &mask_all, &prev_one);
        
        if ((pid = fork()) == 0) { // Child process
            sigprocmask(SIG_SETMASK, &prev_one, NULL);
            setpgid(0,0); // set group id == child process id
            if (execve(token.argv[0], token.argv, environ) < 0 ) {
                sio_printf("failed to execute: %s\n", token.argv[0]);
                exit(0);
            }
            if (in_file != -1) {
                close(in_file);
            }

            if (out_file != -1) {
                close(out_file);
            }
        }
        // parent process

        job_state state = (parse_result == PARSELINE_FG) ? FG : BG;
        jid_t job = add_job(pid, state, cmdline);
        if (in_file != -1) {
            dup2(save_stdin, STDIN_FILENO);
            close(in_file);
        }

        if (out_file != -1) {
            dup2(save_stdout, STDOUT_FILENO);
            close(out_file);
        }   

        if (parse_result == PARSELINE_FG) { //foreground

            wait_fg_job(job, &prev_one);

        } else {
            sio_printf("[%d] (%d) %s \n", job, pid, cmdline);

        }
        sigprocmask(SIG_SETMASK, &prev_one, NULL);
    }

    return;
}

/* Check if command line contains built-in command keyword. Return 0 if not
 * a built-in command. Handle built-in command and return 1
 * 
 * token: struct that stores the result of parsed command line
 */
int builtin_command(struct cmdline_tokens token) {
    
    if (!strcmp(token.argv[0], "quit")) {
        exit(0);
    }

    if (!strcmp(token.argv[0], "jobs")) {
        print_bg_jobs(token);
        return 1;
    }

    if (!strcmp(token.argv[0], "bg")) {
        change_job_state(token.argv[1], false);
        return 1;
    }

    if (!strcmp(token.argv[0], "fg")) {
        change_job_state(token.argv[1], true);
        return 1;
    }
   
   return 0;
}

/* Wait for the foreground job to finish by checking current fg job jid.
 * Temporarily remove signal block while waiting. Restore signal block mask
 * once fg job jid differs from passed in parameter and return.
 * 
 * job: jid of fg job currently running
 * set: signal set that is used when calling sigsuspend
 */
void wait_fg_job(jid_t job, sigset_t *set ) {

    sigset_t mask, prev;

    sigfillset(&mask);
    
    sigprocmask(SIG_BLOCK, &mask, &prev);
    while (job == fg_job()) {
        sigsuspend(set);
    }

    sigprocmask(SIG_SETMASK, &prev, NULL);
    return;
}

/* List jobs in the job list. If token does not contain I/O redirection, the
 * results go to stdout. Otherwise, write results to the designated output 
 * file.
 * 
 * token: struct that stores the result of parsed command line
 * 
 * Error conditions: This function prints out error if output file cannot be
 * opened.
 */
void print_bg_jobs(struct cmdline_tokens token) {

    sigset_t mask, prev;
    sigfillset(&mask);

    int out_file = -1;
    int save_stdout = dup(STDOUT_FILENO);

    if (token.outfile != NULL) {
        out_file = open(token.outfile,O_CREAT|O_RDWR|O_TRUNC , S_IRUSR|S_IWUSR | S_IRGRP|S_IROTH);
        if(out_file < 0) {
            if (errno == EACCES) {
                sio_printf("%s: Permission denied\n", token.outfile);
                return;
            }
        }
        dup2(out_file, STDOUT_FILENO);
    }

    sigprocmask(SIG_BLOCK, &mask, &prev);

    list_jobs(STDOUT_FILENO);
    if (out_file != -1) {
        dup2(save_stdout, STDOUT_FILENO);
        close(out_file);
    }   

    sigprocmask(SIG_SETMASK, &prev, NULL);
    return;
}

/* Sending SIGCONT to stopped job and run it as specified by is_fg. Wait for
 * fg job to finish and return immediately if job is bg.
 * 
 * ptr: pointer to job identifier
 * is_fg: indicates if the job should be run as fg or bg.
 * 
 * Error conditions: This function print out error if job identifier is empty, 
 * invalid, or does not exist in job list.
 */
void change_job_state(char *ptr, bool is_fg) {

    jid_t job;
    sigset_t mask, prev;
    sigfillset(&mask);
    
    char* type = (is_fg) ? "fg" : "bg";
    arg_state as = parse_argument(ptr);

    // No argument 
    if (as == ARG_EMPTY) {
        sio_printf("%s command requires PID or %%jobid argument\n", type);
        return;
    }

    // Argument format invalid
    if (as == ARG_INVALID) {
        sio_printf("%s: argument must be a PID or %%jobid\n", type);
        return;
    }

    sigprocmask(SIG_BLOCK, &mask, &prev);
    if (as == ARG_JID) { 
        job =  (job_exists(atoi(ptr + 1))) ? atoi(ptr + 1) : 0;
    } else { 
        job = job_from_pid(atoi(ptr));
    }

    // No job in job list 
    if (job == 0) {
        sio_printf("%s: No such job\n", ptr);
        sigprocmask(SIG_SETMASK, &prev, NULL);
        return;
    }
   
    job_set_state(job, (is_fg? FG : BG));
    kill(-(job_get_pid(job)), SIGCONT);    

    if (is_fg) {
        wait_fg_job(job, &prev);
    } else {
        sio_printf("[%d] (%d) %s \n", job, job_get_pid(job), job_get_cmdline(job));
    }

    sigprocmask(SIG_SETMASK, &prev, NULL);
    return;
}

/* Return the state of job identifier. Might be empty, invalid, jid, or pid
 * 
 * ptr: pointer to job identifier
 */
arg_state parse_argument(char *ptr) {
    if (ptr == NULL) {
        return ARG_EMPTY;
    }

    char *itr = ((char) (*ptr) == '%') ? (ptr + 1) : ptr;

    while (*itr) {
        if (!isdigit(*itr)) {
            return ARG_INVALID;
        }
        itr++;
    }

    if ((char) (*ptr) == '%') {
        return ARG_JID;
    } else {
        return ARG_PID;
    }
}

/*****************
 * Signal handlers
 *****************/

/*
 * Handles signal SIGCHLD. Delete jobs that finish normally or are terminated
 * by signal. Update job state for jobs are stopped. Save errno when entering
 * and restore errno when leaving the function
 * 
 * sig: signal number
 */
void sigchld_handler(int sig) {

    int olderrno = errno;
    sigset_t mask_all, prev_all;
    int status;
    pid_t pid;

    sigfillset(&mask_all);

    while((pid = waitpid(-1, &status, WNOHANG|WUNTRACED)) > 0) {
        if (WIFEXITED(status)) {
            sigprocmask(SIG_BLOCK, &mask_all, &prev_all);

            delete_job(job_from_pid(pid));
            sigprocmask(SIG_SETMASK, &prev_all, NULL);
        }

        if (WIFSIGNALED(status)) {
            sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
            jid_t jid = job_from_pid(pid);
            sio_printf("Job [%d] (%d) terminated by signal %d\n", jid, pid
                        , WTERMSIG(status));
            delete_job(jid);
            sigprocmask(SIG_SETMASK, &prev_all, NULL);            
        }

        if (WIFSTOPPED(status)) {
            sigprocmask(SIG_BLOCK, &mask_all, &prev_all);
            jid_t jid = job_from_pid(pid);
            sio_printf("Job [%d] (%d) stopped by signal %d\n", jid, pid
                        , WSTOPSIG(status));
            job_set_state(jid, ST);
            sigprocmask(SIG_SETMASK, &prev_all, NULL);  
        }
       
    }

    errno = olderrno;
    return;
}

/*
 * Handles signal SIGINT. Send SIGINT to all the jobs in the same process
 * group as the fg job. Save errno when entering and restore errno when 
 * leaving the function.
 * 
 * sig: signal number
 */
void sigint_handler(int sig) {
    int olderrno = errno;
    sigset_t mask, prev;

    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &prev);
    if (fg_job() != 0) {
        pid_t fg_pid = job_get_pid(fg_job());
        kill(-fg_pid, SIGINT);
    }
    sigprocmask(SIG_SETMASK, &prev, NULL);

    errno = olderrno;
    return;
}

/*
 * Handles signal SIGINT. Send SIGSTP to all the jobs in the same process
 * group as the fg job. Save errno when entering and restore errno when 
 * leaving the function.
 * 
 * sig: signal number
 */
void sigtstp_handler(int sig) {
    int olderrno = errno;
    sigset_t mask, prev;

    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &prev);
    if (fg_job() != 0) {
        pid_t fg_pid = job_get_pid(fg_job());
        kill(-fg_pid, SIGTSTP);
    }
    sigprocmask(SIG_SETMASK, &prev, NULL);

    errno = olderrno;
    return;
}

/*
 * cleanup - Attempt to clean up global resources when the program exits. In
 * particular, the job list must be freed at this time, since it may contain
 * leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT,  SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL);  // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL);  // Handles terminated or stopped child

    destroy_job_list();
}

