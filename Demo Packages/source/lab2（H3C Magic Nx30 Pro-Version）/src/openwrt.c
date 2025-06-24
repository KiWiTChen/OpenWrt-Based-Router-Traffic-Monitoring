#define _DEFAULT_SOURCE
#include <stdlib.h>//system function
#include <unistd.h>//sleep function
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h> 
#include <netinet/ip6.h>
#include <netinet/ether.h> 
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <string.h>
#include <time.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <net/if.h>

#define BUFSIZE 65535
#define MAX_IPS 1024

typedef struct {
    char peer_ip[INET6_ADDRSTRLEN];  // 对端IP地址
    int is_upload;//为0代表是下载，为1是上传
    int is_ipv6;  // 是否为IPv6
    uint32_t bytes_1s[10];           // 每秒记录（最多保留10秒）
    int head;                        // 环形缓冲头指针
    uint32_t total;                 // 总流量
    char dns_name[NI_MAXHOST];      //​记录解析出来的域名，如果没有则不会被赋值
    uint32_t max;                   //记录峰值
} TrafficRecord;
//结构体，用来记录抓到的数据包

TrafficRecord traffic_table[MAX_IPS];//创造一个记录数组
int traffic_count = 0;
pthread_mutex_t traffic_lock = PTHREAD_MUTEX_INITIALIZER;
//互斥锁来保护对 traffic_table 和 traffic_count 的访问



char ipv4_addr[INET6_ADDRSTRLEN];
char ipv6_addr[INET6_ADDRSTRLEN];
//定义两个全局变量用来储存网络接口的ipv4和ipv6地址
//INET6_ADDRSTRLEN:指定 IPv6 地址字符串的最大长度

//=================【用于统计的哈希表操作函数】===================
TrafficRecord* find_or_create_record(const char* peer_ip, int is_upload,int is_ipv6) {
    //// 遍历 traffic_table，查找匹配的记录
    for (int i = 0; i < traffic_count; i++) {
        if (strcmp(traffic_table[i].peer_ip, peer_ip) == 0 &&
            traffic_table[i].is_ipv6 == is_ipv6 && traffic_table[i].is_upload == is_upload) {
            return &traffic_table[i];//// 找到匹配记录，返回记录指针
        }
    }
    //// 如果未找到匹配记录，尝试创建新记录
    if (traffic_count < MAX_IPS) {
        TrafficRecord* rec = &traffic_table[traffic_count++];
        memset(rec, 0, sizeof(TrafficRecord));
        strcpy(rec->peer_ip, peer_ip);
        rec->is_upload = is_upload;
        rec->is_ipv6 = is_ipv6;
        return rec;// // 返回新记录指针
    }
    return NULL;//  // 如果 traffic_table 已满，返回 NULL
}


void callback(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet) {
    //定义一个名为 callback 的函数，它接收三个参数：user：用户自定义数据指针，通常用于传递额外的信息，但在此函数中未使用。header：指向 pcap_pkthdr 结构的指针，包含捕获的数据包的头部信息，如时间戳和长度。packet：指向捕获的数据包内容的指针。

    // 1. 打印时间戳
    time_t raw_time = header->ts.tv_sec;
    struct tm *timeinfo = localtime(&raw_time);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", timeinfo);
    //从 header 中提取时间戳，并将其转换为本地时间格式，然后存储在 time_str 中。

    // 2. 获取以太网头并判断类型
    //一个标准的以太网帧头部总共有 14 字节（6 + 6 + 2）
    //用下面这个结构体来储存头部信息
    struct ether_header {
        u_char ether_dhost[6];//​6位目的MAC地址
        u_char ether_shost[6];//6位源MAC地址
        u_short ether_type;//​2位存储以太网帧的类型字段。
    };
    const struct ether_header *eth = (struct ether_header *)packet;
    //定义一个 ether_header 结构体，用于表示以太网帧头部。将 packet 强制转换为 ether_header 类型，并从中提取以太网类型字段。使用 ntohs 函数将网络字节序转换为主机字节序。
    //packet 指向的内存区域的前 14 字节正好符合 struct ether_header 的内存布局

    u_short eth_type = ntohs(eth->ether_type);
    //以太网帧头部中的 ether_type 字段是网络字节序（大端序），需要使用 ntohs 函数将其转换为主机字节序。
    
    // 准备变量
    char src_ip[INET6_ADDRSTRLEN] = "";
    char dst_ip[INET6_ADDRSTRLEN] = "";
    char src_host[NI_MAXHOST] = "";
    char dst_host[NI_MAXHOST] = "";
    //定义变量，用于储存源/ 目的 IP、主机名

    // 3. IPv4 处理
    if (eth_type == 0x0800) {
        const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        //struct ip 是用于表示 IPv4 头部的结构体
        //获的数据包的前 14 个字节是 以太网帧头部，而 IPv4 头部 位于以太网帧头部之后
        //跳过以太网头部（14 字节），指向 IPv4 头部的起始位置。将 packet 强制转换为 struct ip 类型的指针，指向 IPv4 头部。可以方便地访问 IPv4 头部的字段
        
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, sizeof(dst_ip));
        //inet_ntop 是一个用于将网络字节序的 IP 地址转换为可读的字符串格式的函数
        //AF_INET->IPv4 
        //将目的ip地址和源ip地址转换为字符串形式后储存在先前定义的变量中

        // 反向DNS解析，仅当IP地址不等于本机IP时才解析（本机ip不用解析）
        if (strcmp(src_ip, ipv4_addr) != 0) {
            struct sockaddr_in src_in;//用于存储IPv4地址和端口号的结构体。
            memset(&src_in, 0, sizeof(src_in));//将src_in结构体清零，确保所有字段都被初始化。
            src_in.sin_family = AF_INET;//设置地址族为IPv4。
            src_in.sin_addr = ip_header->ip_src;//源IP地址（ip_header->ip_src）赋值给src_in.sin_addr。
            getnameinfo((struct sockaddr *)&src_in, sizeof(src_in), src_host, sizeof(src_host), NULL, 0, NI_NAMEREQD);
            //getnameinfo：用于将网络地址（如IP地址）转换为可读的主机名。
            //(struct sockaddr *)&src_in：指向struct sockaddr_in结构体的指针，包含要解析的IP地址。
            //sizeof(src_in)：struct sockaddr_in结构体的大小。
            //src_host：目标缓冲区，用于存储解析后的主机名。
            //sizeof(src_host)：目标缓冲区的大小。
            //NULL 和 0：不解析服务名（端口号）。
            //NI_NAMEREQD：标志，表示如果无法解析主机名，则返回错误。
        }

        if (strcmp(dst_ip, ipv4_addr) != 0) {
            struct sockaddr_in dst_in;
            memset(&dst_in, 0, sizeof(dst_in));
            dst_in.sin_family = AF_INET;
            dst_in.sin_addr = ip_header->ip_dst;
            getnameinfo((struct sockaddr *)&dst_in, sizeof(dst_in), dst_host, sizeof(dst_host), NULL, 0, NI_NAMEREQD);
        }

    }

    //总结
    //如果以太网类型字段表示 IPv4 数据包（0x0800），则处理 IPv4 数据包。将 packet 偏移以指向 IP 头部，并提取源 IP 和目的 IP 地址。
    //使用 inet_ntop 函数将 IP 地址转换为可读的字符串格式。根据源 IP 和目的 IP 地址与本地 IP 地址的比较结果，设置数据包方向。

    // 4. IPv6 处理
    //同上
    else if (eth_type == 0x86DD) {
        const struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, sizeof(dst_ip));

        // 反向DNS解析，仅当IP地址不等于本机IPv6时才解析
        if (strcmp(src_ip, ipv6_addr) != 0) {
            struct sockaddr_in6 src6;
            memset(&src6, 0, sizeof(src6));
            src6.sin6_family = AF_INET6;
            src6.sin6_addr = ip6_header->ip6_src;
            getnameinfo((struct sockaddr *)&src6, sizeof(src6), src_host, sizeof(src_host), NULL, 0, NI_NAMEREQD);
        }
        if (strcmp(dst_ip, ipv6_addr) != 0) {
            struct sockaddr_in6 dst6;
            memset(&dst6, 0, sizeof(dst6));
            dst6.sin6_family = AF_INET6;
            dst6.sin6_addr = ip6_header->ip6_dst;
            getnameinfo((struct sockaddr *)&dst6, sizeof(dst6), dst_host, sizeof(dst_host), NULL, 0, NI_NAMEREQD);
        }

    }
    //如果以太网类型字段表示 IPv6 数据包（如 0x86DD），则处理 IPv6 数据包。将 packet 偏移以指向 IPv6 头部，并提取源 IP 和目的 IP 地址。
    //使用 inet_ntop 函数将 IP 地址转换为可读的字符串格式。根据源 IP 和目的 IP 地址与本地 IP 地址的比较结果，设置数据包方向。

    // 5. 打印统一输出
    if (src_ip[0] != '\0' && dst_ip[0] != '\0') {//确保 src_ip 和 dst_ip 都已经被成功赋值
        pthread_mutex_lock(&traffic_lock);//互斥锁（mutex），用于保护 traffic_table 和 traffic_count 共享资源

        int is_upload = 0;
        const char* peer_ip = NULL;//存储对端ip地址,const 修饰符用于声明变量的值在初始化后不能被修改,保护数据的完整性
        int is_ipv6_flag = (eth_type == 0x86DD); // 标识是否是IPv6

        // 同时判断是否是本机IPv4或IPv6地址
        int is_src_self = (strcmp(src_ip, ipv4_addr) == 0 || strcmp(src_ip, ipv6_addr) == 0);
        int is_dst_self = (strcmp(dst_ip, ipv4_addr) == 0 || strcmp(dst_ip, ipv6_addr) == 0);

        if (is_src_self && !is_dst_self) {//ip结构中的源ip是主机ip，代表是上传
            is_upload= 1;
            peer_ip = dst_ip;
        } else if (is_dst_self && !is_src_self) {//下载
            is_upload = 0;
            peer_ip = src_ip;
        } else {
            pthread_mutex_unlock(&traffic_lock);
            return; // 与本机无关或是本机间通信，不计
        }

        TrafficRecord* rec = find_or_create_record(peer_ip, is_upload,is_ipv6_flag);
        //在记录数组中更新记录
        if (rec) {
            if(src_host[0] != '\0'){
                strcpy(rec->dns_name,src_host);
            }
            if(dst_host[0] != '\0'){
                strcpy(rec->dns_name,src_host);
            }
            //若dns解析成功，记录中加入dns域名

            rec->total += header->len;//将当前数据包的长度（header->len）加到记录的总流量（rec->total）中
            rec->bytes_1s[rec->head] += header->len;//这一步将当前数据包的长度（header->len）加到记录的每秒流量统计中.rec->bytes_1s 是一个环形缓冲区，用于存储每秒的流量统计。rec->head 是环形缓冲区的头指针，指向当前秒的流量统计位置。
        }

        pthread_mutex_unlock(&traffic_lock);//释放锁
     }
    }


    //=================【打印线程】===================
void* print_thread(void* arg) {
    while (1) {
        sleep(1);
        //间隔1s打印一次

        pthread_mutex_lock(&traffic_lock);

        for (int i = 0; i < traffic_count; i++) {
            if (traffic_table[i].bytes_1s[traffic_table[i].head] > traffic_table[i].max){
                traffic_table[i].max = traffic_table[i].bytes_1s[traffic_table[i].head] ;
            }//更新峰值

            // 滑动窗口：head 每秒前进一步，并清除新位置的数据
            traffic_table[i].head = (traffic_table[i].head + 1) % 10;
            traffic_table[i].bytes_1s[traffic_table[i].head] = 0;
        }

        // 清屏 + 打印表头
        system("clear");
        printf("IPaddress            direction   IPaddress                   3s   5s   10s   total  10sAverage  Max\n");
        printf("-------------------------------------------------------------------------------------------------\n");

        int printed[MAX_IPS] = {0};

        for (int i = 0; i < traffic_count; i++) {
            TrafficRecord* rec = &traffic_table[i];

            // 准备统计 rec 的流量
            uint32_t sum3_rec = 0, sum5_rec = 0, sum10_rec = 0;
            for (int k = 0; k < 10; k++) {
                int idx = (rec->head + 10 - 1 - k + 10) % 10;//目的是计算环形缓冲区中相对于头指针 rec->head 的第 k 个元素的索引
                if (k < 3) sum3_rec += rec->bytes_1s[idx];
                if (k < 5) sum5_rec += rec->bytes_1s[idx];
                sum10_rec += rec->bytes_1s[idx];
            }

            uint32_t total_combined = rec->total;

            // 打印一行合并结果
            const char* self_ip = rec->is_ipv6 ? ipv6_addr : ipv4_addr;//对端ip是什么格式主机ip就打印什么格式
            printf("%-24s %-6s %-24s %6u %6u %6u %6u %6.1f %6d\n",
                self_ip,
                rec->is_upload ? "=>" : "<=",
                rec->dns_name[0] == '\0'?rec->peer_ip:rec->dns_name,
                sum3_rec,
                sum5_rec,
                sum10_rec,
                total_combined,
                sum10_rec / 10.0,
                rec -> max);
        }

        pthread_mutex_unlock(&traffic_lock);
    }
    return NULL;
}




void print_addresses(char device_name[256]) {
    //用于打印网络接口信息
    //输入参数是选中的接口名字
    struct ifaddrs *ifaddr, *ifa;
    //定义两个指针，用于存储和遍历网络接口信息。
    //结构体struct ifaddrs：ifa_next：指向下一个网络接口信息的指针。ifa_name：接口名称（如eth0）。ifa_addr：指向接口地址的指针（如IPv4或IPv6地址）。ifa_netmask：指向接口的子网掩码。ifa_ifu：联合体，包含其他信息（如广播地址或点对点地址）。ifa_flags：接口标志（如IFF_UP表示接口已启用）。
    //注意，同一网络接口的信息储存不一定连续.每一个结点只是某个接口的一个信息，如ipv4或ipv6或mac

    if (getifaddrs(&ifaddr) == -1) {
        //获取当前主机的所有网络接口信息，并将链表的头指针存储在ifaddr中
        perror("getifaddrs");
        return;
    }

    printf("%sThe following table describes the interface information：\n",device_name);
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        //作用：遍历所有网络接口信息。ifa从链表头开始，逐个访问每个接口信息，直到ifa为NULL。
        if ((strcmp(ifa->ifa_name,device_name)!=0)) continue;
        //不是想找的接口就跳过

        //sa_family字段：
        //AF_INET：表示IPv4地址。
        //AF_INET6：表示IPv6地址。
        //AF_PACKET：表示链路层地址（如MAC地址）。
        // 获取 IPv4 地址
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            //将ifa_addr强制转换为struct sockaddr_in类型，用于处理IPv4地址
            //结构体struct sockaddr_in：sin_family：地址族（AF_INET）。sin_port：端口号。sin_addr：IPv4地址。
            inet_ntop(AF_INET, &(addr->sin_addr), ipv4_addr, sizeof(ipv4_addr));
            //inet_ntop函数：输入：AF_INET：表示IPv4地址。&(addr->sin_addr)：指向IPv4地址的指针。ip：存储转换后的字符串。sizeof(ip)：目标字符串的长度。
            //输出：将IPv4地址转换为点分十进制字符串。
            //作用：将地址结构转换为可读的字符串形式。
            printf("  IPv4 address: %s\n", ipv4_addr);
        }

        // 获取 IPv6 地址
        else if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)ifa->ifa_addr;
            //作用：将ifa_addr强制转换为struct sockaddr_in6类型，用于处理IPv6地址。
            //结构体struct sockaddr_in6：sin6_family：地址族（AF_INET6）。sin6_port：端口号。sin6_addr：IPv6地址。sin6_scope_id：作用域ID（用于链路本地地址）。
            inet_ntop(AF_INET6, &(addr->sin6_addr), ipv6_addr, sizeof(ipv6_addr));
            //同上
            printf("  IPv6 address: %s\n", ipv6_addr);
        }

        // 获取 MAC 地址
        else if (ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
            //作用：将ifa_addr强制转换为struct sockaddr_ll类型，用于处理链路层地址。
            //结构体struct sockaddr_ll：sll_family：地址族（AF_PACKET）。sll_protocol：协议类型。sll_ifindex：接口索引。sll_hatype：硬件类型sll_pkttype：包类型。sll_halen：硬件地址长度。sll_addr：硬件地址（如MAC地址）。
            printf("  MAC address: ");
            for (int i = 0; i < s->sll_halen; i++) {
                //以xx:xx:xx:xx:xx:xx的格式打印MAC地址。
                printf("%02x%c", s->sll_addr[i], (i + 1 != s->sll_halen) ? ':' : '\n');
            }
        }

    }

    freeifaddrs(ifaddr);
}


int main(){
     /*                                                    */
    //1.列出当前系统上所有可用的网络接口，打印名称和其具体信息（如果有的话）

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_findalldevs(&alldevs, errbuf);
    //alldevs：pcap_if_t结构体指针，用于存储查找到的所有网络设备信息。 
    //errbuf：C语言字符串缓存区用于缓冲错误信息。s

    printf("The following table describes the network interface of the host:\n");
    for (pcap_if_t *pdev = alldevs; pdev != NULL; pdev = pdev->next){
        printf("%s %s\n", pdev->name, pdev->description ? pdev->description : "");
    }
    //循环打印网络设备信息

    pcap_freealldevs(alldevs);
    //释放pcap_if_t结构体指针

    //pcap_if_t 结构体用于表示系统中的网络接口。它包含接口的名称、描述以及链表中下一个接口的指针。pcap_if_t 结构体通常用于列出系统中所有的网络接口。
    //pcap_t 结构体是一个更复杂的结构体，用于表示一个活动的捕获句柄。它包含了捕获会话所需的所有信息，如过滤器、捕获长度、超时等。

    /*                                                    */
    //2.根据1中打印得到的网络设备，输入选择打开的设备名称，打开该设备

    char device_name[256];
    //存放输入的设备名称
    
    pcap_t *handle;
    //存放句柄

    printf("Enter the name of the device you want to listen to: ");
    scanf("%s", device_name);
    //获取监听的设备名称

    while(!(handle = pcap_open_live(device_name, BUFSIZ, 1, 1000, errbuf))){
        //pcap_open_live 函数用于打开名为 "device_name" 的网络设备，捕获长度设置为 65535 字节，使用混杂模式，超时时间为 1000 毫秒。如果打开设备失败，错误信息将被存储在 errbuf 中。
        //捕获长度（snaplen）是指在数据包捕获过程中，每个数据包实际被捕获并存储的最大字节数。
        //混杂模式是一种网络接口的工作模式，当网络接口设置为混杂模式时，它将接收所有经过它的数据包，而不仅仅是那些发给该接口或发自该接口的数据包。
        //这些参数是在调用pcap_loop() 或 pcap_next_ex()函数时起作用，该函数只起到设置这些参数并打开的作用

        printf("The opening failed, and the error message is as follows：");
        printf("%s",errbuf);
        printf("\nEnter the name of the device you want to listen to:");
        scanf("%s", device_name);
    }
    printf("Successfully opened%s\n",device_name);
    //注意，运行时要在终端手动用root权限运行，否则pcap_open_live(device_name, BUFSIZ, 1, 1000, errbuf)返回的永远是Null（权限不够），错误信息为You don't have permission to capture on that device 

    /*                                                    */
    //3.打印选中网络接口的Mac地址，ipv4地址和ipv6地址
     print_addresses(device_name);


    /*                                                    */
    //4.设置过滤规则：只捕获IP包
    struct bpf_program fp;
    //定义一个类型为 bpf_program 的变量 fp。这个结构体用于存储由 pcap_compile() 编译后的伯克利包过滤器（BPF）程序。
    char filter_exp[] = "ip or ip6";
    //定义一个字符数组 filter_exp 并初始化为字符串 "ip or ip6"。这个字符串是一个过滤表达式，用于指定想要捕获的数据包类型，即 IPv4（ip）和 IPv6（ip6）数据包
     if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        //调用 pcap_compile() 函数编译过滤表达式。参数解释：handle：一个指向 pcap_t 结构的指针，表示一个打开的网络设备。&fp：指向 bpf_program 结构的指针，用于存储编译后的过滤程序。filter_exp：指向过滤表达式的指针。0：优化标志，设置为 0 表示不进行优化。PCAP_NETMASK_UNKNOWN：网络掩码，设置为未知，表示 libpcap 不应假设任何子网掩码。
        fprintf(stderr, "过滤规则编译失败: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 3;
    }
    // 应用过滤规则
    if (pcap_setfilter(handle, &fp) == -1) {
        //调用 pcap_setfilter() 函数将编译后的过滤程序应用到打开的网络设备上。如果应用失败，函数返回 -1
        fprintf(stderr, "设置过滤规则失败: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 4;
    }


    /*                                                    */
    //5.开始在这个网络设备上循环捕获网络数据包并开启线程打印
    printf("After 5s the IP packet capture starts：\n");
    sleep(5);
    pthread_t tid;
    pthread_create(&tid, NULL, print_thread, NULL);

    if(pcap_loop(handle,-1,callback,NULL)==-1){
        //handle	打开的设备句柄（来自 pcap_open_live()）
        //cnt	要捕获的包数，10 表示回调函数最多执行 10 次；-1 表示无限制（直到出错或调用 pcap_breakloop()）
        //callback	每次抓到一个数据包，就会调用这个回调函数 
        //user	传给回调函数的自定义数据（可为 NULL，也可以传结构体指针）
        //前文设置的超时时间是1000ms，意思如果在1000ms时间内到达了多个数据包 这些包都会被缓存在内核缓冲区； 到了1000ms时间，或者缓存满了，libpcap会一次性传给程序； 然后callback()会被逐个触发，每个包调用一次。
        printf("\nCapture failed");
        return 1;
    }
    

    pcap_close(handle);
    return 1;
    
}