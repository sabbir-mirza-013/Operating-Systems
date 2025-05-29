#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>

#define MAX_INPUT_SIZE 1024
#define MAX_ARGS 64
#define MAX_PIPES 10
#define MAX_HISTORY 20

// Global variables
char *history[MAX_HISTORY];
int history_count = 0;
int running_command = 0;

void handle_sigint(int sig) {
    printf("\nUse 'exit' to quit the shell.\n");
}

// Signal handler for CTRL+C
/*void handle_sigint(int sig) {
    if (running_command) {
        // Do nothing here, let the child process handle it
        printf("\n");
    } else {
        // If no command is running, just print a new prompt line
        printf("\nsh> ");
        fflush(stdout);
    }
}*/

// Function to add command to history
void add_to_history(char *cmd) {
    if (cmd[0] == '\0') return; // Don't add empty commands
    
    // If history is full, free the oldest command
    if (history_count == MAX_HISTORY) {
        free(history[0]);
        for (int i = 0; i < MAX_HISTORY - 1; i++) {
            history[i] = history[i + 1];
        }
        history_count--;
    }
    
    char *cmd_copy = strdup(cmd);
    if (cmd_copy == NULL) {
        perror("strdup");
        return;
    }
    
    history[history_count++] = cmd_copy;
}

// Function to display history
void display_history() {
    for (int i = 0; i < history_count; i++) {
        printf("%d: %s\n", i + 1, history[i]);
    }
}

// Function to parse command into arguments with quote handling
int parse_command(char *cmd, char **args) {
    int count = 0;
    int i = 0;
    int arg_start = 0;
    int in_single_quotes = 0;
    int in_double_quotes = 0;
    char current_arg[MAX_INPUT_SIZE] = {0};
    int current_arg_pos = 0;
    
    while (cmd[i] != '\0' && count < MAX_ARGS - 1) {
        // Handle quotes
        if (cmd[i] == '\'' && !in_double_quotes) {
            in_single_quotes = !in_single_quotes;
            i++;
            continue;
        } else if (cmd[i] == '\"' && !in_single_quotes) {
            in_double_quotes = !in_double_quotes;
            i++;
            continue;
        }
        
        // If we're not in quotes and see whitespace, we've reached the end of an argument
        if (!in_single_quotes && !in_double_quotes && (cmd[i] == ' ' || cmd[i] == '\t' || cmd[i] == '\n')) {
            if (current_arg_pos > 0) {
                current_arg[current_arg_pos] = '\0';
                args[count] = strdup(current_arg);
                if (args[count] == NULL) {
                    perror("strdup");
                    return count;
                }
                count++;
                current_arg_pos = 0;
                memset(current_arg, 0, MAX_INPUT_SIZE);
            }
        } else {
            // Add this character to the current argument
            current_arg[current_arg_pos++] = cmd[i];
        }
        
        i++;
    }
    
    // Add the last argument if there is one
    if (current_arg_pos > 0) {
        current_arg[current_arg_pos] = '\0';
        args[count] = strdup(current_arg);
        if (args[count] == NULL) {
            perror("strdup");
            return count;
        }
        count++;
    }
    
    // Check for unclosed quotes
    if (in_single_quotes || in_double_quotes) {
        fprintf(stderr, "Error: Unclosed quotes\n");
    }
    
    args[count] = NULL;
    return count;
}

// Function to execute a single command with redirections
int execute_command(char *cmd) {
    char *args[MAX_ARGS];
    char *input_file = NULL;
    char *output_file = NULL;
    int append_output = 0;
    int i, arg_count;
    int exit_status = 0;
    
    // Make a copy of the command since parse_command modifies it
    char *cmd_copy = strdup(cmd);
    if (cmd_copy == NULL) {
        perror("strdup");
        return 1;  // Return error code
    }
    
    arg_count = parse_command(cmd_copy, args);
    
    if (arg_count == 0) {
        free(cmd_copy);
        return 0;  // Empty command, not an error
    }
    
    // Check for redirections
    for (i = 0; i < arg_count; i++) {
        if (strcmp(args[i], "<") == 0) {
            // Input redirection
            if (i + 1 < arg_count) {
                input_file = args[i + 1];
                // Remove redirection symbols and filename from args
                args[i] = NULL;
                i++; // Skip the filename in the next iteration
            }
        } else if (strcmp(args[i], ">") == 0) {
            // Output redirection
            if (i + 1 < arg_count) {
                output_file = args[i + 1];
                append_output = 0;
                args[i] = NULL;
                i++;
            }
        } else if (strcmp(args[i], ">>") == 0) {
            // Append output
            if (i + 1 < arg_count) {
                output_file = args[i + 1];
                append_output = 1;
                args[i] = NULL;
                i++;
            }
        }
    }
    
    // Built-in command: exit
    if (strcmp(args[0], "exit") == 0) {
        // Clean up history before exiting
        for (i = 0; i < history_count; i++) {
            free(history[i]);
        }
        free(cmd_copy);
        exit(0);
    }
    
    // Built-in command: history
    if (strcmp(args[0], "history") == 0) {
        display_history();
        free(cmd_copy);
        return 0;  // Success
    }
    
    // Built-in command: cd
    if (strcmp(args[0], "cd") == 0) {
        if (args[1] == NULL) {
            // cd with no args - go to home directory
            char *home = getenv("HOME");
            if (home == NULL) {
                fprintf(stderr, "cd: HOME environment variable not set\n");
                free(cmd_copy);
                return 1;  // Error
            } else if (chdir(home) != 0) {
                perror("cd");
                free(cmd_copy);
                return 1;  // Error
            }
        } else {
            // cd with a directory argument
            if (chdir(args[1]) != 0) {
                perror("cd");
                free(cmd_copy);
                return 1;  // Error
            }
        }
        free(cmd_copy);
        return 0;  // Success
    }
    
    // Fork and execute the command
    pid_t pid = fork();
    
    if (pid < 0) {
        perror("fork");
        free(cmd_copy);
        return 1;  // Error
    } else if (pid == 0) {
        // Child process
        
        // Handle input redirection
        if (input_file) {
            int fd = open(input_file, O_RDONLY);
            if (fd < 0) {
                perror("open");
                exit(EXIT_FAILURE);
            }
            dup2(fd, STDIN_FILENO);
            close(fd);
        }
        
        // Handle output redirection
        if (output_file) {
            int flags = O_WRONLY | O_CREAT;
            if (append_output) {
                flags |= O_APPEND;
            } else {
                flags |= O_TRUNC;
            }
            
            int fd = open(output_file, flags, 0644);
            if (fd < 0) {
                perror("open");
                exit(EXIT_FAILURE);
            }
            dup2(fd, STDOUT_FILENO);
            close(fd);
        }
        
        // Execute the command
        execvp(args[0], args);
        
        // If execvp returns, it means an error occurred
        perror("execvp");
        exit(EXIT_FAILURE);
    } else {
        // Parent process
        running_command = 1;
        int status;
        waitpid(pid, &status, 0);
        running_command = 0;
        
        // Get exit status
        if (WIFEXITED(status)) {
            exit_status = WEXITSTATUS(status);
        } else {
            exit_status = 1;  // Consider non-normal termination as failure
        }
    }
    
    free(cmd_copy);
    return exit_status;  // Return the exit status of the command
}

// Function to execute piped commands
int execute_piped_commands(char *cmd) {
    char *commands[MAX_PIPES + 1];
    int num_commands = 0;
    char *token;
    int exit_status = 0;
    
    // Make a copy because strtok modifies the string
    char *cmd_copy = strdup(cmd);
    if (cmd_copy == NULL) {
        perror("strdup");
        return 1;  // Error
    }
    
    // Parse the input into separate commands
    token = strtok(cmd_copy, "|");
    while (token != NULL && num_commands < MAX_PIPES + 1) {
        // Remove leading and trailing spaces
        char *trimmed = token;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
        
        // Store the command
        commands[num_commands++] = trimmed;
        token = strtok(NULL, "|");
    }
    
    if (num_commands == 1) {
        // No pipes, just execute the command
        exit_status = execute_command(commands[0]);
        free(cmd_copy);
        return exit_status;
    }
    
    // Set up pipes
    int pipes[MAX_PIPES][2];
    for (int i = 0; i < num_commands - 1; i++) {
        if (pipe(pipes[i]) < 0) {
            perror("pipe");
            free(cmd_copy);
            return 1;  // Error
        }
    }
    
    // Execute commands with pipes
    pid_t pids[MAX_PIPES + 1];  // Store child process IDs
    
    for (int i = 0; i < num_commands; i++) {
        pids[i] = fork();
        
        if (pids[i] < 0) {
            perror("fork");
            free(cmd_copy);
            return 1;  // Error
        } else if (pids[i] == 0) {
            // Child process
            
            // Set up input redirection from previous pipe (if not first command)
            if (i > 0) {
                dup2(pipes[i-1][0], STDIN_FILENO);
            }
            
            // Set up output redirection to next pipe (if not last command)
            if (i < num_commands - 1) {
                dup2(pipes[i][1], STDOUT_FILENO);
            }
            
            // Close all pipe fds
            for (int j = 0; j < num_commands - 1; j++) {
                close(pipes[j][0]);
                close(pipes[j][1]);
            }
            
            // Parse and execute the command with redirections
            char *subcmd_copy = strdup(commands[i]);
            if (subcmd_copy == NULL) {
                perror("strdup");
                exit(EXIT_FAILURE);
            }
            
            // Check for redirections (similar to execute_command)
            char *args[MAX_ARGS];
            char *input_file = NULL;
            char *output_file = NULL;
            int append_output = 0;
            int arg_count = parse_command(subcmd_copy, args);
            
            // Check for redirections
            for (int k = 0; k < arg_count; k++) {
                if (strcmp(args[k], "<") == 0) {
                    // Input redirection (only consider if this is the first command)
                    if (i == 0 && k + 1 < arg_count) {
                        input_file = args[k + 1];
                        args[k] = NULL;
                        k++;
                    }
                } else if (strcmp(args[k], ">") == 0) {
                    // Output redirection (only consider if this is the last command)
                    if (i == num_commands - 1 && k + 1 < arg_count) {
                        output_file = args[k + 1];
                        append_output = 0;
                        args[k] = NULL;
                        k++;
                    }
                } else if (strcmp(args[k], ">>") == 0) {
                    // Append output (only consider if this is the last command)
                    if (i == num_commands - 1 && k + 1 < arg_count) {
                        output_file = args[k + 1];
                        append_output = 1;
                        args[k] = NULL;
                        k++;
                    }
                }
            }
            
            // Handle input redirection for the first command
            if (input_file) {
                int fd = open(input_file, O_RDONLY);
                if (fd < 0) {
                    perror("open");
                    free(subcmd_copy);
                    exit(EXIT_FAILURE);
                }
                dup2(fd, STDIN_FILENO);
                close(fd);
            }
            
            // Handle output redirection for the last command
            if (output_file) {
                int flags = O_WRONLY | O_CREAT;
                if (append_output) {
                    flags |= O_APPEND;
                } else {
                    flags |= O_TRUNC;
                }
                
                int fd = open(output_file, flags, 0644);
                if (fd < 0) {
                    perror("open");
                    free(subcmd_copy);
                    exit(EXIT_FAILURE);
                }
                dup2(fd, STDOUT_FILENO);
                close(fd);
            }
            
            execvp(args[0], args);
            
            // If execvp returns, it means an error occurred
            perror("execvp");
            free(subcmd_copy);
            exit(EXIT_FAILURE);
        }
    }
    
    // Parent process: close all pipe fds
    for (int i = 0; i < num_commands - 1; i++) {
        close(pipes[i][0]);
        close(pipes[i][1]);
    }
    
    // Wait for all child processes to finish
    running_command = 1;
    int status;
    
    // Wait for the last command in the pipe, which determines the overall exit status
    waitpid(pids[num_commands - 1], &status, 0);
    
    if (WIFEXITED(status)) {
        exit_status = WEXITSTATUS(status);
    } else {
        exit_status = 1;  // Consider non-normal termination as failure
    }
    
    // Wait for the other commands to avoid zombies
    for (int i = 0; i < num_commands - 1; i++) {
        waitpid(pids[i], NULL, 0);
    }
    
    running_command = 0;
    
    free(cmd_copy);
    return exit_status;
}

// Function to execute multiple commands separated by semicolons
int execute_semicolon_commands(char *cmd) {
    // Create a copy of the input to avoid modifying it
    char *cmd_copy = strdup(cmd);
    if (cmd_copy == NULL) {
        perror("strdup");
        return 1;  // Error
    }
    
    // Count the number of semicolons
    int semicolon_count = 0;
    for (char *p = cmd_copy; *p; p++) {
        if (*p == ';') semicolon_count++;
    }
    
    // Allocate space for commands
    char **commands = malloc((semicolon_count + 1) * sizeof(char *));
    if (!commands) {
        perror("malloc");
        free(cmd_copy);
        return 1;  // Error
    }
    
    // Parse the commands
    int cmd_index = 0;
    char *start = cmd_copy;
    char *p;
    
    for (p = cmd_copy; *p; p++) {
        if (*p == ';') {
            *p = '\0';  // Replace semicolon with null terminator
            commands[cmd_index++] = start;
            start = p + 1;  // Move start to the next command
        }
    }
    
    // Add the last command
    commands[cmd_index++] = start;
    
    // Execute each command - return status of the last command
    int exit_status = 0;
    
    for (int i = 0; i < cmd_index; i++) {
        // Trim leading spaces
        char *trimmed = commands[i];
        while (*trimmed && (*trimmed == ' ' || *trimmed == '\t')) trimmed++;
        
        if (*trimmed) {  // Skip empty commands
            // Check if the command contains pipes
            if (strchr(trimmed, '|') != NULL) {
                // Contains pipes
                exit_status = execute_piped_commands(trimmed);
            } else {
                // Single command
                exit_status = execute_command(trimmed);
            }
        }
    }
    
    free(commands);
    free(cmd_copy);
    return exit_status;  // Return the exit status of the last command
}

// Function to execute commands with AND (&&) logic
int execute_and_commands(char *cmd) {
    // Make a copy of the command because strtok modifies the string
    char *cmd_copy = strdup(cmd);
    if (cmd_copy == NULL) {
        perror("strdup");
        return 1;  // Error
    }
    
    char *commands[MAX_ARGS]; // Array to store AND-separated commands
    int num_commands = 0;
    
    // Split the command by &&
    char *token = strtok(cmd_copy, "&&");
    while (token != NULL && num_commands < MAX_ARGS) {
        // Remove leading and trailing spaces
        char *trimmed = token;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
        
        // Store the command
        commands[num_commands++] = trimmed;
        token = strtok(NULL, "&&");
    }
    
    // Execute commands sequentially, stopping if one fails
    int exit_status = 0;
    
    for (int i = 0; i < num_commands; i++) {
        // Check if the command contains semicolons
        if (strchr(commands[i], ';') != NULL) {
            exit_status = execute_semicolon_commands(commands[i]);
        }
        // Check if the command contains pipes
        else if (strchr(commands[i], '|') != NULL) {
            exit_status = execute_piped_commands(commands[i]);
        }
        // Otherwise, just execute a single command
        else {
            exit_status = execute_command(commands[i]);
        }
        
        // If any command fails, stop the chain
        if (exit_status != 0) {
            break;
        }
    }
    
    free(cmd_copy);
    return exit_status;
}

// Main shell function
int main() {
    char input[MAX_INPUT_SIZE];
    signal(SIGINT, handle_sigint);
    /*struct sigaction sa;
    
    // Set up signal handler for CTRL+C
    sa.sa_handler = handle_sigint;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);*/
    
    while (1) {
        printf("sh> ");
        fflush(stdout);
        
        // Read input
        if (fgets(input, MAX_INPUT_SIZE, stdin) == NULL) {
            // Handle EOF (CTRL+D)
            printf("\n");
            break;
        }
        
        // Remove newline character
        input[strcspn(input, "\n")] = '\0';
        
        // Add command to history
        add_to_history(input);
        
        // Check if the input contains "&&"
        if (strstr(input, "&&") != NULL) {
            execute_and_commands(input);
        }
        // Check if the input contains semicolons
        else if (strchr(input, ';') != NULL) {
            execute_semicolon_commands(input);
        }
        // Check if the input contains pipes
        else if (strchr(input, '|') != NULL) {
            execute_piped_commands(input);
        }
        // Otherwise, just execute a single command
        else {
            execute_command(input);
        }
    }
    
    // Clean up history before exiting
    for (int i = 0; i < history_count; i++) {
        free(history[i]);
    }
    
    return 0;
}
