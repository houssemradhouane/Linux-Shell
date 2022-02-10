#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <glob.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "readcmd.h"

#define NR_JOBS 50
#define PATH_BUFSIZE 2048

#define BACKGROUND_EXECUTION 0
#define FOREGROUND_EXECUTION 1
#define PIPELINE_EXECUTION 2

#define STATUS_RUNNING 0
#define STATUS_DONE 1
#define STATUS_SUSPENDED 2

#define COMMAND_EXTERNAL 0
#define COMMAND_EXIT 1
#define COMMAND_CD 2
#define COMMAND_JOBS 3
#define COMMAND_FG 4
#define COMMAND_BG 5
#define COMMAND_STOP 6

const char* STATUS_STRING[] = {
    "running",
    "done",
    "suspended"
};

struct process {
    char **command;
    pid_t pid;
    char *input_path;
    char *output_path;
    int type;
    int status;
    struct process* nprocess;
};

struct job {
    int id;
    struct process *root;
    char **command;
    pid_t pgid;
    int mode;
};

struct shell_info {
    char cur_dir[PATH_BUFSIZE];
    char pw_dir[PATH_BUFSIZE];
    struct job *jobs[NR_JOBS + 1];
};

struct shell_info *shell;

// fonction pour l'affichage de l'invite
void showCP() {
     printf("\033[0;31m");
     printf("shr-3.2$");
     printf("\033[0m");
}

char** copy_command(char** command) {
       int i = 0;
       while (command[i] != NULL) {
            i++;
       }
       char** new_command = malloc(i*sizeof(char*));
       for (int j = 0; j<i; j++) {
           new_command[j] = strdup(command[j]);
       }
       return new_command;
}

// fonction pour trouver la commande à éxecuter
int get_command_type(char *command) {
    if (strcmp(command, "exit") == 0) {
        return COMMAND_EXIT;
    } else if (strcmp(command, "cd") == 0) {
        return COMMAND_CD;
    } else if (strcmp(command, "jobs") == 0) {
        return COMMAND_JOBS;
    } else if (strcmp(command, "fg") == 0) {
        return COMMAND_FG;
    } else if (strcmp(command, "bg") == 0) {
        return COMMAND_BG;
    } else if (strcmp(command, "stop") == 0) {
        return COMMAND_STOP;
    } else {
        return COMMAND_EXTERNAL;
    }
}



// fonction pour initialiser quelques paramètres d'un processus
struct process* initialize_process(struct job *job) {
     struct process *new_proc = (struct process*) malloc(sizeof(struct process));
     new_proc->pid = -1;
     new_proc->type = get_command_type(job->command[0]);
     return new_proc;
}

// fonction pour mettre à jour le status d'un processus
int set_process_status(struct process *proc, int status) {
    proc->status = status;
    return 0;

}

// fonction qui prend un pid et met à jour le status du processus concerné
int set_process_status_pid(int pid, int status) {
    int i;
    struct process *proc;

    for (i = 1; i <= NR_JOBS; i++) {
        if (shell->jobs[i] == NULL) {
            continue;
        }
        for (proc = shell->jobs[i]->root; proc != NULL; proc = proc->nprocess) {
            if (proc->pid == pid) {
                proc->status = status;
                return 0;
            }
        }
    }

    return -1;
}


// fonction pour trouver le prochain id disponible pour un job
int get_next_available_id() {
    int i;
    for (i = 1; i <= NR_JOBS; i++) {
        if (shell->jobs[i] == NULL) {
            return i;
        }
    }
    return -1;
}

//fonction pour insérer le job dans la table à jobs
int insert_job(struct job *job) {
    int id = get_next_available_id();
    if (id < 0) {
        return -1;
    }
    job->id = id;
    shell->jobs[id] = job;
    return id;
}

// fonction pour initialiser quelques paramètres d'un job
struct job* initialize_job(struct cmdline *commandline) {
     struct job *new_job = (struct job*) malloc(sizeof(struct job));
     struct process *proc, *nproc,*nproc2;
     char ***parsed;
     parsed = commandline->seq;
     new_job->command = parsed[0];
     new_job->pgid = -1;
     if ( commandline->backgrounded) {
        new_job->mode = BACKGROUND_EXECUTION;
     } else {
        new_job->mode = FOREGROUND_EXECUTION;
     }
     proc = initialize_process(new_job);
     proc->command = copy_command(parsed[0]);
     if (parsed[1] != NULL) {
        int i = 1;
        nproc = (struct process*) malloc(sizeof(struct process));
        nproc->command = copy_command(parsed[1]);
        nproc->pid = -1;
        nproc->type = get_command_type(parsed[1][0]);
        nproc->input_path = NULL;
        nproc->output_path = NULL;
        nproc->nprocess = NULL;
        proc->input_path = commandline->in;
        proc->output_path = NULL;
        proc->nprocess = nproc;
        i++;
        while (parsed[i] != NULL) {
              nproc2 = (struct process*) malloc(sizeof(struct process));
              nproc2->command = copy_command(parsed[i]);
              nproc2->pid = -1;
              nproc2->type = get_command_type(parsed[i][0]);
              nproc2->input_path = NULL;
              nproc2->output_path = NULL;
              nproc2->nprocess = NULL;
              nproc->nprocess = nproc2;
              nproc=nproc2;
              i++;
        }
       nproc->nprocess = NULL;
       nproc->output_path=commandline->out;
     } else {
        nproc = NULL;
        proc->input_path = commandline->in;
        proc->output_path = commandline->out;
        proc->nprocess = nproc;
     }
     new_job->root = proc;
     return new_job;
}

// fonction qui supprime un job du tableau jobs
int remove_job(int id) {
    if (id > NR_JOBS || shell->jobs[id] == NULL) {
        return -1;
    }

    free(shell->jobs[id]);
    shell->jobs[id] = NULL;

    return 0;
}

// fonction pour trouver l'id job par son pid
int find_job_id(int pid) {
    int i;

    for (i = 1; i <= NR_JOBS; i++) {
        if (shell->jobs[i] != NULL) {
                if (shell->jobs[i]->pgid == pid) {
                    return i;
                }
        }
    }

    return -1;
}

// fonction pour trouver un job par son id
struct job* get_job_by_id(int id) {
    if (id > NR_JOBS) {
        return NULL;
    }

    return shell->jobs[id];
}

// fonction pour trouver un job par son pgid
int get_job_id_by_pgid(int pgid) {
    int i;

    for (i = 1; i <= NR_JOBS; i++) {
        if (shell->jobs[i] != NULL) {
            if(shell->jobs[i]->pgid == pgid) {
                    return i;
            }
        }
    }

    return -1;
}

// fonction pour trouver le pgid par l'id du job
int get_pgid_by_job_id(int id) {
    struct job *job = get_job_by_id(id);

    if (job == NULL) {
        return -1;
    }

    return job->pgid;
}
// fonction qui affiche la commande d'un process
void print_process_command(char** command) {
     int i = 0;
     char* token;
     while (command[i] != NULL ) {
           token = strdup(command[i]);
           printf("%s", token);
           printf(" ");
           i++;
     }
}

// fonction qui affiche le status d'un job
int print_job_status(int id) {
    if (id > NR_JOBS || shell->jobs[id] == NULL) {
        return -1;
    }
    printf("[%d]", id);

    struct process *proc;
    for (proc = shell->jobs[id]->root; proc != NULL; proc = proc->nprocess) {
        printf("\t%d\t%s\t", proc->pid,
            STATUS_STRING[proc->status]);
        print_process_command(proc->command);
        if (proc->nprocess != NULL) {
            printf("|\n");
        } else {
            printf("\n");
        }
    }

    return 0;
}



// fonction pour le waitpid et pour gérer l'état du fils (celle de moodle)
int wait_for_pid(int pid) {
    int status = 0;
    struct job* job;

    waitpid(pid, &status, WUNTRACED);
    int id = get_job_id_by_pgid(pid);
    job=get_job_by_id(id);
    if (WIFEXITED(status)) {
        set_process_status(job->root, STATUS_DONE);
    } else if (WSTOPSIG(status)) {
        status = -1;
        set_process_status(job->root, STATUS_SUSPENDED);
    }
   
    return status;
}

// fonction qui compte le nombre de process actifs pour un job
int get_nb_proc(int id) {
    if (id > NR_JOBS || shell->jobs[id] == NULL) {
        return -1;
    }

    int count = 0;
    struct process *proc;
    for (proc = shell->jobs[id]->root; proc != NULL; proc = proc->nprocess) {
        if  (proc->status != STATUS_DONE) {
            count++;
        }
    }

    return count;
}

// fonction qui gère l'état d'un job (inspirée par celle donnée sur moodle)
int wait_for_job(int id) {
    if (id > NR_JOBS || shell->jobs[id] == NULL) {
        return -1;
    }
    int proc_count = get_nb_proc(id);
    int wait_pid = -1, wait_count = 0;
    int status = 0;
    do {
        wait_pid = waitpid(-shell->jobs[id]->pgid, &status, WUNTRACED);
        wait_count++;
        if (WIFEXITED(status)) {
            set_process_status_pid(wait_pid, STATUS_DONE);
        } else if (WSTOPSIG(status)) {
            status = -1;
            set_process_status_pid(wait_pid, STATUS_SUSPENDED);
        }
    } while (wait_count < proc_count);
    return status;
}


// fonction pour éxécuter exit
int exec_exit() {
    printf("au revoir!\n");
    exit(0);
}

void exec_update_cwd_info() {
    getcwd(shell->cur_dir, sizeof(shell->cur_dir));
}

// fonction pour éxécuter cd
int exec_cd(char** argv) {
    if (argv[1] == NULL) {
        chdir(shell->pw_dir);
        exec_update_cwd_info();
        return 0;
    }

    if (chdir(argv[1]) == 0) {
        exec_update_cwd_info();
        return 0;
    } else {
        printf("shr: cd %s: No such file or directory\n", argv[1]);
        return 0;
    }
}

// fonction pour exécuter fg
int exec_fg(struct process* proc) {
    char **argv = proc->command;
    if (argv[1] == NULL) {
        printf("usage: fg <pid>\n");
        return -1;
    }

    pid_t pid;
    int job_id = atoi(argv[1]);
    pid = get_pgid_by_job_id(job_id);

    if (kill(pid, SIGCONT) < 0) {
        printf("shr: fg %d: job not found\n", pid);
        return -1;
    }

    tcsetpgrp(0, pid);

    if (job_id > 0) {
        set_process_status(proc, STATUS_RUNNING);
        if (wait_for_job(job_id) >= 0) {
            remove_job(job_id);
        }
    } else {
        wait_for_pid(pid);
    }
    signal(SIGTTOU, SIG_IGN);
    tcsetpgrp(0, getpid());
    signal(SIGTTOU, SIG_DFL);

    return 0;
}

// fonction pour exécuter bg
int exec_bg(struct process* proc) {
    char **argv = proc->command;
    if (argv[1] == NULL) {
        printf("usage: bg <pid>\n");
        return -1;
    }

    pid_t pid;
    int job_id = atoi(argv[1]);
    pid = get_pgid_by_job_id(job_id);

    if (kill(pid, SIGCONT) < 0) {
        printf("shr: bg %d: job not found\n", pid);
        return -1;
    }

    if (job_id > 0) {
        set_process_status(proc, STATUS_RUNNING);
    }

    return 0;
}

// fonction pour éxecuter stop
int exec_stop(struct process* proc) {
    char **argv = proc->command;
    if (argv[1] == NULL) {
        printf("usage: stop <pid>\n");
        return -1;
    }

    pid_t pid;
    int job_id = atoi(argv[1]);
    pid = get_pgid_by_job_id(job_id);
    if (kill(pid, SIGSTOP) < 0) {
        printf("shr: stop %d: job not found\n", pid);
        return 0;
    }

    if (job_id > 0) {
        set_process_status(proc, STATUS_SUSPENDED);
        if (wait_for_job(job_id) >= 0) {
            remove_job(job_id);
        }
    }

    return 1;
}
// fonction pour exécuter jobs
int exec_jobs() {
    int i;

    for (i = 0; i < NR_JOBS; i++) {
        if (shell->jobs[i] != NULL) {
            print_job_status(i);
        }
    }

    return 0;
}
// fonction pour éxecuter les commandes internes
int execBuiltin(struct process *proc) {
    int status = 1;

    switch (proc->type) {
        case COMMAND_EXIT:
            exec_exit();
            break;
        case COMMAND_CD:
            exec_cd(proc->command);
            break;
        case COMMAND_JOBS:
            exec_jobs();
            break;
        case COMMAND_STOP:
            exec_stop(proc);
            break;
        case COMMAND_FG:
            exec_fg(proc);
            break;
        case COMMAND_BG:
            exec_bg(proc);
            break;
        default:
            status = 0;
            break;
    }

    return status;
}

// fonction pour vérifier si le tableau jobs contient des zombies
void clear_zombies() {
    int status, pid, id;
    struct job* job;
    while ((pid = waitpid(-1, &status, WNOHANG|WUNTRACED|WCONTINUED)) > 0) {
        id = find_job_id(pid);
        job = shell->jobs[id];
        if (WIFEXITED(status)) {
            set_process_status_pid(pid, STATUS_DONE);
        } else if (WIFSTOPPED(status)) {
            set_process_status_pid(pid, STATUS_SUSPENDED);
        } 
        if (id > 0 && job->root->status == 1) {
            remove_job(id);
        }
    }
}

// fonction pour lancer un process
int launch_process(struct job *job, struct process *proc, int in_fd, int out_fd, int mode) {
    proc->status = STATUS_RUNNING;
    if (proc->type != COMMAND_EXTERNAL && execBuiltin(proc)) {
        return 0;
    }

    pid_t childpid;
    int status = 0;
    
    // forking a child
    childpid = fork();

    if (childpid < 0) {
        printf("\nFailed to fork a child\n\n");
        return -1;
    //fils
    } else if (childpid == 0) {
        signal(SIGINT, SIG_DFL);
        signal(SIGQUIT, SIG_DFL);
        signal(SIGTSTP, SIG_DFL);
        signal(SIGTTIN, SIG_DFL);
        signal(SIGTTOU, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);

        proc->pid = getpid();
        if (job->pgid > 0) {
            setpgid(0, job->pgid);
        } else {
            job->pgid = proc->pid;
            setpgid(0, job->pgid);
        }
        if (in_fd != 0) {
            dup2(in_fd, 0);
            close(in_fd);
        }

        if (out_fd != 1) {
            dup2(out_fd, 1);
            close(out_fd);
        }
        if (execvp(proc->command[0], proc->command) < 0) {
            printf("shr: %s: command not found\n", proc->command[0]);
            exit(0);
        }

        exit(0);
    //père
    } else {
        proc->pid = childpid;
        if (job->pgid > 0) {
            setpgid(childpid, job->pgid);
        } else {
            job->pgid = proc->pid;
            setpgid(childpid, job->pgid);
        }

        if (mode == FOREGROUND_EXECUTION) {
            tcsetpgrp(0, job->pgid);
            status = wait_for_job(job->id);
            signal(SIGTTOU, SIG_IGN);
            tcsetpgrp(0, getpid());
            signal(SIGTTOU, SIG_DFL);
        }
    }
    return status;
}

// fonction pour lancer un job
int launch_job(struct job *job) {
    struct process *proc;
    int status = 0, in_fd = 0, fd[2], job_id = -1;

    clear_zombies();
    if (job->root->type == COMMAND_EXTERNAL) {
        job_id = insert_job(job);
    }

    for (proc = job->root; proc != NULL; proc = proc->nprocess) {
        if (proc == job->root && proc->input_path != NULL) {
            in_fd = open(proc->input_path, O_RDONLY);
            if (in_fd < 0) {
                printf("mysh: no such file or directory: %s\n", proc->input_path);
                remove_job(job_id);
                return -1;
            }
        }
        if (proc->nprocess != NULL) {
            pipe(fd);
            status = launch_process(job, proc, in_fd, fd[1], PIPELINE_EXECUTION);
            close(fd[1]);
            in_fd = fd[0];
        } else {
            int out_fd = 1;
            if (proc->output_path != NULL) {
                out_fd = open(proc->output_path, O_CREAT|O_WRONLY);
                if (out_fd < 0) {
                    out_fd = 1;
                }
            }
            status = launch_process(job, proc, in_fd, out_fd, job->mode);
        }
    }

    if (job->root->type == COMMAND_EXTERNAL) {
        if (status >= 0 && job->mode == FOREGROUND_EXECUTION) {
            remove_job(job_id);
        }
    }
    return status;
}



void sigint_handler(int signal) {
    printf("\n");
}

// fonction pour intialiser le shell
void init_shell() {
    struct sigaction sigint_action = {
        .sa_handler = &sigint_handler,
        .sa_flags = 0
    };
    sigemptyset(&sigint_action.sa_mask);
    sigaction(SIGINT, &sigint_action, NULL);
    sigaction(SIGTSTP, &sigint_action, NULL);

    shell = (struct shell_info*) malloc(sizeof(struct shell_info));

    struct passwd *pw = getpwuid(getuid());
    strcpy(shell->pw_dir, pw->pw_dir);

    int i;
    for (i = 0; i < NR_JOBS; i++) {
        shell->jobs[i] = NULL;
    }

    exec_update_cwd_info();
}
      
int main () {

    struct job *new_job;
    struct cmdline *commandline;
    
     init_shell();
     while (1) {
        // afficher l'invite
        showCP();
        // lire l'entrée
        siginterrupt(SIGSTOP,1);
        siginterrupt(SIGTSTP,1);
        siginterrupt(SIGINT,1);
        siginterrupt(SIGKILL,1);
        // masquage de SIGINT et SIGTSTP
        sigset_t ens ;
        sigemptyset(&ens);
        sigaddset(&ens,SIGTSTP);
        sigaddset(&ens,SIGINT);
        sigprocmask(SIG_BLOCK,&ens,NULL);
        commandline = readcmd();
        sigprocmask(SIG_UNBLOCK,&ens,NULL);
        if (commandline->err != 0) {
            clear_zombies();
            continue;
        }
        if (commandline->seq[0] != NULL) {
           new_job = initialize_job(commandline);
           launch_job(new_job);
        }
    }
}
    


