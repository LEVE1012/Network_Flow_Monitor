#include <pcap.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#define MAX_NODES 1024
#define WIN_SIZE 40
#define JSON_FILE_PATH "/www/web/data.json"

pthread_mutex_t lockTable = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    char address[64];
    int flowDir;
    unsigned long totalBytes;
    unsigned long maxRate;
    double avg10, avg20, avg30;
    unsigned long windowBuf[WIN_SIZE];
    unsigned long snapshots[WIN_SIZE];
    int pos;
} TrafficNode;

TrafficNode nodePool[MAX_NODES];
int nodeCount = 0;

void rotateWindow();
void dumpJsonFile(const char* path);
void recordFlow(const char* ip, int dir, int size);
void inspectPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void applyFilter(pcap_t* handle, const char* expr);

void gracefulExit(int sig) {
    printf("[EXIT] Cleaning data and shutting down gracefully...\n");
    pthread_mutex_lock(&lockTable);
    nodeCount = 0;
    memset(nodePool, 0, sizeof(nodePool));
    pthread_mutex_unlock(&lockTable);

    int fd = open(JSON_FILE_PATH, O_WRONLY | O_TRUNC | O_CREAT, 0666);
    if (fd >= 0) {
        write(fd, "[]\n", 3);
        close(fd);
        printf("[OK] Cleared JSON content.\n");
    } else {
        perror("[ERR] Cannot open JSON file");
    }
    exit(0);
}

void applyFilter(pcap_t* handle, const char* expr) {
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, expr, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "[ERR] Filter failure: %s\n", pcap_geterr(handle));
        exit(1);
    }
}

void recordFlow(const char* ip, int dir, int size) {
    pthread_mutex_lock(&lockTable);
    for (int i = 0; i < nodeCount; ++i) {
        if (strcmp(nodePool[i].address, ip) == 0 && nodePool[i].flowDir == dir) {
            nodePool[i].totalBytes += size;
            nodePool[i].windowBuf[nodePool[i].pos] += size;
            nodePool[i].snapshots[nodePool[i].pos] += size;
            pthread_mutex_unlock(&lockTable);
            return;
        }
    }

    if (nodeCount < MAX_NODES) {
        strncpy(nodePool[nodeCount].address, ip, sizeof(nodePool[nodeCount].address) - 1);
        nodePool[nodeCount].flowDir = dir;
        nodePool[nodeCount].totalBytes = size;
        memset(nodePool[nodeCount].windowBuf, 0, sizeof(nodePool[nodeCount].windowBuf));
        memset(nodePool[nodeCount].snapshots, 0, sizeof(nodePool[nodeCount].snapshots));
        nodePool[nodeCount].windowBuf[0] = size;
        nodePool[nodeCount].snapshots[0] = size;
        nodePool[nodeCount].pos = 0;
        nodeCount++;
    }
    pthread_mutex_unlock(&lockTable);
}

void inspectPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ipHdr = (struct ip *)(packet + 14);
    const char* src = inet_ntoa(ipHdr->ip_src);
    const char* dst = inet_ntoa(ipHdr->ip_dst);

    if (strncmp(dst, "224.", 4) == 0 || strcmp(dst, "255.255.255.255") == 0)
        return;

    int isLan = strncmp(src, "192.168", 7) == 0 || strncmp(src, "10.", 3) == 0;
    recordFlow(isLan ? dst : src, isLan ? 0 : 1, header->len);
}

void rotateWindow() {
    pthread_mutex_lock(&lockTable);
    for (int i = 0; i < nodeCount; ++i) {
        nodePool[i].pos = (nodePool[i].pos + 1) % WIN_SIZE;
        nodePool[i].windowBuf[nodePool[i].pos] = 0;
        nodePool[i].snapshots[nodePool[i].pos] = 0;
    }
    pthread_mutex_unlock(&lockTable);
}

void dumpJsonFile(const char* path) {
    pthread_mutex_lock(&lockTable);
    FILE* fp = fopen(path, "w");
    if (!fp) {
        perror("fopen");
        pthread_mutex_unlock(&lockTable);
        return;
    }
    fprintf(fp, "[\n");
    for (int i = 0; i < nodeCount; ++i) {
        TrafficNode *p = &nodePool[i];
        unsigned long s10 = 0, s20 = 0, s30 = 0, peak = 0;
        for (int j = 0; j < 10; ++j) s10 += p->windowBuf[(p->pos + WIN_SIZE - j) % WIN_SIZE];
        for (int j = 0; j < 20; ++j) s20 += p->windowBuf[(p->pos + WIN_SIZE - j) % WIN_SIZE];
        for (int j = 0; j < 30; ++j) s30 += p->windowBuf[(p->pos + WIN_SIZE - j) % WIN_SIZE];
        for (int j = 0; j < WIN_SIZE; ++j)
            if (p->windowBuf[j] > peak) peak = p->windowBuf[j];

        p->avg10 = s10 / 10.0;
        p->avg20 = s20 / 20.0;
        p->avg30 = s30 / 30.0;
        p->maxRate = peak;

        fprintf(fp,
            "  {\"ip\":\"%s\", \"dir\":\"%s\", \"total\":%lu, \"peak\":%lu, \"avg10\":%.1f, \"avg20\":%.1f, \"avg30\":%.1f, \"bytes\":[",
            p->address, p->flowDir ? "IN" : "OUT", p->totalBytes, p->maxRate, p->avg10, p->avg20, p->avg30);
        for (int j = 0; j < WIN_SIZE; ++j) {
            int idx = (p->pos + 1 + j) % WIN_SIZE;
            fprintf(fp, "%lu%s", p->snapshots[idx], (j < WIN_SIZE - 1) ? "," : "");
        }
        fprintf(fp, "]}%s\n", (i == nodeCount - 1) ? "" : ",");
    }
    fprintf(fp, "]\n");
    fclose(fp);
    pthread_mutex_unlock(&lockTable);
}

void* runExporter(void* arg) {
    while (1) {
        dumpJsonFile(JSON_FILE_PATH);
        sleep(2);
    }
    return NULL;
}

void* runRotator(void* arg) {
    while (1) {
        rotateWindow();
        sleep(2);
    }
    return NULL;
}

int main(int argc, char* argv[]) {
    char iface[32] = "eth0";
    if (argc > 1) strncpy(iface, argv[1], 31);

    pthread_mutex_init(&lockTable, NULL);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *cap = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (!cap) {
        fprintf(stderr, "[ERR] Failed to open interface: %s\n", errbuf);
        return 1;
    }

    const char* expr = "ip and not multicast";
    applyFilter(cap, expr);

    signal(SIGINT, gracefulExit);
    signal(SIGTERM, gracefulExit);

    pthread_t t1, t2;
    pthread_create(&t1, NULL, runExporter, NULL);
    pthread_create(&t2, NULL, runRotator, NULL);
    pthread_detach(t1);
    pthread_detach(t2);

    while (1) {
        pcap_dispatch(cap, 0, inspectPacket, NULL);
        usleep(50000);
    }

    pcap_close(cap);
    pthread_mutex_destroy(&lockTable);
    return 0;
}