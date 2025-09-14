/*
 * Simple tool to convert .net binary files to JSON format
 * Uses the existing response reading infrastructure
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Response type definitions */
#define RESP_PACKET	1
#define RESP_SOCKNAME	2
#define RESP_DSTADDR	3
#define RESP_PEERNAME	4
#define RESP_PROTO	4
#define RESP_RCVDTTL	5
#define RESP_RCVDTCLASS	6
#define RESP_SENDTO	7
#define RESP_ADDRINFO	8
#define RESP_ADDRINFO_SA	9
#define RESP_TTL	4
#define RESP_TIMEOFDAY	4
#define RESP_READ_ERROR	4
#define RESP_N_RESOLV	4
#define RESP_RESOLVER	5
#define RESP_LENGTH	6
#define RESP_DATA	7
#define RESP_CMSG	8
#define RESP_TIMEOUT	9
#define RESP_ADDRINFO_10	10

/* Response type names for JSON output */
static const char* get_response_type_name(int type) {
    if (type == RESP_PACKET) return "RESP_PACKET";
    if (type == RESP_SOCKNAME) return "RESP_SOCKNAME";
    if (type == RESP_DSTADDR) return "RESP_DSTADDR";
    if (type == RESP_PEERNAME) return "RESP_PEERNAME";
    if (type == RESP_TTL) return "RESP_TTL";
    if (type == RESP_TIMEOUT) return "RESP_TIMEOUT";
    if (type == RESP_READ_ERROR) return "RESP_READ_ERROR";
    if (type == RESP_LENGTH) return "RESP_LENGTH";
    if (type == RESP_PROTO) return "RESP_PROTO";
    if (type == RESP_RCVDTTL) return "RESP_RCVDTTL";
    if (type == RESP_RCVDTCLASS) return "RESP_RCVDTCLASS";
    if (type == RESP_SENDTO) return "RESP_SENDTO";
    if (type == RESP_CMSG) return "RESP_CMSG";
    if (type == RESP_DATA) return "RESP_DATA";
    if (type == RESP_ADDRINFO) return "RESP_ADDRINFO";
    if (type == RESP_ADDRINFO_SA) return "RESP_ADDRINFO_SA";
    if (type == RESP_RESOLVER) return "RESP_RESOLVER";
    if (type == RESP_N_RESOLV) return "RESP_N_RESOLV";
    if (type == RESP_TIMEOFDAY) return "RESP_TIMEOFDAY";
    return "UNKNOWN";
}

/* Convert sockaddr to JSON representation */
static void json_write_sockaddr(FILE *fh, const char *field_name, 
                               const struct sockaddr *sa, socklen_t salen) {
    char addr_str[INET6_ADDRSTRLEN];
    int port = 0;
    const char *family_str = "AF_UNKNOWN";
    
    if (sa == NULL || salen == 0) {
        fprintf(fh, ", \"%s\": null", field_name);
        return;
    }
    
    switch (sa->sa_family) {
        case AF_INET: {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
            family_str = "AF_INET";
            port = ntohs(sin->sin_port);
            inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
            break;
        }
        case AF_INET6: {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
            family_str = "AF_INET6";
            port = ntohs(sin6->sin6_port);
            inet_ntop(AF_INET6, &sin6->sin6_addr, addr_str, sizeof(addr_str));
            break;
        }
        default:
            fprintf(fh, ", \"%s\": {\"family\":\"%s\"}", field_name, family_str);
            return;
    }
    
    /* Write complete sockaddr info as JSON object */
    fprintf(fh, ", \"%s\": {\"family\":\"%s\",\"address\":\"%s\",\"port\":%d", 
            field_name, family_str, addr_str, port);
    
    /* Add IPv6-specific fields if applicable */
    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
        fprintf(fh, ",\"flowinfo\":%u,\"scope_id\":%u", 
                sin6->sin6_flowinfo, sin6->sin6_scope_id);
    }
    
    fprintf(fh, "}");
}

/* Write packet data as hex string */
static void json_write_packet_data(FILE *fh, const char *field_name,
                                  const void *data, size_t len) {
    if (data == NULL || len == 0) {
        fprintf(fh, ", \"%s\": null", field_name);
        return;
    }
    
    fprintf(fh, ", \"%s\": \"", field_name);
    const unsigned char *bytes = (const unsigned char *)data;
    for (size_t i = 0; i < len; i++) {
        fprintf(fh, "%02x", bytes[i]);
    }
    fprintf(fh, "\"");
}

/* Write JSON representation of response data */
static void write_response_json(FILE *file, int type, size_t size, void *data) {
    fprintf(file, "{\"type\":%d,\"type_name\":\"%s\",\"size\":%zu", 
            type, get_response_type_name(type), size);
    
    /* Handle different response types */
    if (type == RESP_DSTADDR || type == RESP_SOCKNAME || type == RESP_PEERNAME) {
        if (data && size >= sizeof(struct sockaddr)) {
            json_write_sockaddr(file, "sockaddr", (struct sockaddr*)data, size);
        }
    } else if (type == RESP_PACKET) {
        if (data && size > 0) {
            json_write_packet_data(file, "packet_data", data, size);
        }
    } else if (type == RESP_TTL || type == RESP_RCVDTTL || type == RESP_RCVDTCLASS) {
        if (data && size > 0) {
            if (size == sizeof(uint8_t)) {
                fprintf(file, ",\"value\":%d", *(uint8_t*)data);
            } else if (size == sizeof(uint16_t)) {
                fprintf(file, ",\"value\":%d", *(uint16_t*)data);
            } else if (size == sizeof(uint32_t)) {
                fprintf(file, ",\"value\":%u", *(uint32_t*)data);
            }
        }
    } else if (type == RESP_PROTO) {
        if (data && size == sizeof(uint8_t)) {
            fprintf(file, ",\"protocol\":%d", *(uint8_t*)data);
        }
    } else if (type == RESP_LENGTH) {
        if (data && size > 0) {
            if (size == sizeof(uint32_t)) {
                fprintf(file, ",\"length\":%u", *(uint32_t*)data);
            } else if (size == sizeof(uint16_t)) {
                fprintf(file, ",\"length\":%d", *(uint16_t*)data);
            }
        }
    } else if (type == RESP_TIMEOUT || type == RESP_READ_ERROR) {
        /* These are typically empty responses */
    } else {
        /* For unknown types, include raw data as hex */
        if (data && size > 0) {
            json_write_packet_data(file, "raw_data", data, size);
        }
    }
    
    fprintf(file, "}");
}

/* Process a single binary file and convert to JSON */
int process_file(const char *input_file, const char *output_file) {
    FILE *in_fp, *out_fp;
    int type;
    size_t size;
    void *data;
    int response_count = 0;
    
    printf("Processing %s -> %s\n", input_file, output_file);
    
    in_fp = fopen(input_file, "rb");
    if (!in_fp) {
        printf("  Error: Cannot open input file\n");
        return -1;
    }
    
    out_fp = fopen(output_file, "w");
    if (!out_fp) {
        printf("  Error: Cannot create output file\n");
        fclose(in_fp);
        return -1;
    }
    
    /* Write JSON header */
    fprintf(out_fp, "{\n");
    fprintf(out_fp, "  \"version\": \"2.0\",\n");
    fprintf(out_fp, "  \"source\": \"net_to_json converter\",\n");
    fprintf(out_fp, "  \"original_file\": \"%s\",\n", input_file);
    fprintf(out_fp, "  \"responses\": [\n");
    
    /* Read responses until EOF */
    while (1) {
        /* Read type */
        if (fread(&type, sizeof(type), 1, in_fp) != 1) {
            break; /* EOF */
        }
        
        /* Read size */
        if (fread(&size, sizeof(size), 1, in_fp) != 1) {
            break; /* EOF */
        }
        
        /* Allocate buffer for data */
        data = malloc(size);
        if (!data) {
            printf("  Error: Memory allocation failed\n");
            break;
        }
        
        /* Read data */
        if (fread(data, size, 1, in_fp) != 1) {
            printf("  Error: Failed to read data\n");
            free(data);
            break;
        }
        
        /* Write JSON response */
        if (response_count > 0) {
            fprintf(out_fp, ",\n");
        }
        fprintf(out_fp, "    ");
        write_response_json(out_fp, type, size, data);
        
        free(data);
        response_count++;
    }
    
    /* Write JSON footer */
    fprintf(out_fp, "\n  ],\n");
    fprintf(out_fp, "  \"total_responses\": %d\n", response_count);
    fprintf(out_fp, "}\n");
    
    fclose(in_fp);
    fclose(out_fp);
    
    printf("  ✓ Success (%d responses)\n", response_count);
    return 0;
}

void print_usage(const char *progname) {
    printf("Usage: %s [options] <input_file> [output_file]\n", progname);
    printf("       %s [options] <input_dir> <output_dir>\n", progname);
    printf("\nOptions:\n");
    printf("  -h, --help     Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s evhttpget-4.net evhttpget-4.json\n", progname);
    printf("  %s testsuite/evhttpget-data/ testsuite-json/\n", progname);
}

int main(int argc, char *argv[]) {
    int opt;
    const char *input_path = NULL;
    const char *output_path = NULL;
    
    /* Parse command line options */
    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    if (argc - optind < 1) {
        print_usage(argv[0]);
        return 1;
    }
    
    input_path = argv[optind];
    output_path = argv[optind + 1];
    
    if (!output_path) {
        /* Generate output filename from input */
        char *output_name = strdup(input_path);
        char *dot = strrchr(output_name, '.');
        if (dot) *dot = '\0';
        output_path = malloc(strlen(output_name) + 6);
        sprintf((char*)output_path, "%s.json", output_name);
        free(output_name);
    }
    
    struct stat st;
    if (stat(input_path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            /* Process directory */
            DIR *dir = opendir(input_path);
            if (!dir) {
                printf("Error: Cannot open directory %s\n", input_path);
                return 1;
            }
            
            /* Create output directory */
            char mkdir_cmd[1024];
            snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", output_path);
            system(mkdir_cmd);
            
            struct dirent *entry;
            while ((entry = readdir(dir)) != NULL) {
                if (strstr(entry->d_name, ".net") != NULL) {
                    char input_file[1024];
                    char output_file[1024];
                    char *output_name = strdup(entry->d_name);
                    char *dot = strrchr(output_name, '.');
                    if (dot) *dot = '\0';
                    
                    snprintf(input_file, sizeof(input_file), "%s/%s", input_path, entry->d_name);
                    snprintf(output_file, sizeof(output_file), "%s/%s.json", output_path, output_name);
                    
                    process_file(input_file, output_file);
                    free(output_name);
                }
            }
            closedir(dir);
        } else {
            /* Process single file */
            return process_file(input_path, output_path);
        }
    } else {
        printf("Error: Input path does not exist\n");
        return 1;
    }
    
    return 0;
}
