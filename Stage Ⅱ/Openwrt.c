#include <stdio.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <string.h>
#include <time.h>

#define BUFSIZE 65535

void callback(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet) {
    //参数含义
    //unsigned char *user  用途：传递给回调函数的用户自定义数据指针。 由调用 pcap_loop() 时的第四个参数传入。作用：允许在回调中访问外部变量或状态，比如统计结构体、上下文信息。 如果不需要用，可以传 NULL。
    //const struct pcap_pkthdr *header 用途：指向当前捕获到的数据包头部信息。包含内容：ts：数据包捕获的时间戳（秒 + 微秒）。caplen：实际捕获的数据包长度（可能小于原始包大小）。len：数据包的原始长度（未截断的长度）。作用：获取数据包的时间信息；得知抓取的数据长度，便于统计和处理。
    //const unsigned char *packet 用途：指向捕获到的原始数据包内容（字节数组）。作用：可以解析这个字节流，按协议格式（以太网、IP、TCP/UDP等）提取数据；例如，获取源IP、目的IP、端口等；或保存数据包内容供后续分析。

    // 1. 打印抓到的包的时间戳
    time_t raw_time = header->ts.tv_sec;
    struct tm *timeinfo = localtime(&raw_time);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", timeinfo);

    // 2. 打印包长度
    printf("\n捕获到一个数据包，时间：%s，长度：%d 字节", time_str, header->len);
}

int main(){
     /*                                                    */
    //1.列出当前系统上所有可用的网络接口，打印名称和其具体信息（如果有的话）

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_findalldevs(&alldevs, errbuf);
    //alldevs：pcap_if_t结构体指针，用于存储查找到的所有网络设备信息。 
    //errbuf：C语言字符串缓存区用于缓冲错误信息。s

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

    printf("输入你想要监听的设备名称: ");
    scanf("%s", device_name);
    //获取监听的设备名称

    while(!(handle = pcap_open_live(device_name, BUFSIZ, 1, 1000, errbuf))){
        //pcap_open_live 函数用于打开名为 "device_name" 的网络设备，捕获长度设置为 65535 字节，使用混杂模式，超时时间为 1000 毫秒。如果打开设备失败，错误信息将被存储在 errbuf 中。
        //捕获长度（snaplen）是指在数据包捕获过程中，每个数据包实际被捕获并存储的最大字节数。
        //混杂模式是一种网络接口的工作模式，当网络接口设置为混杂模式时，它将接收所有经过它的数据包，而不仅仅是那些发给该接口或发自该接口的数据包。
        //这些参数是在调用pcap_loop() 或 pcap_next_ex()函数时起作用，该函数只起到设置这些参数并打开的作用

        printf("打开失败，错误信息如下：");
        printf("%s",errbuf);
        printf("\n输入你想要监听的设备名称: ");
        scanf("%s", device_name);
    }
    printf("成功打开%s",device_name);
    //注意，运行时要在终端手动用root权限运行，否则pcap_open_live(device_name, BUFSIZ, 1, 1000, errbuf)返回的永远是Null（权限不够），错误信息为You don't have permission to capture on that device 

    /*                                                    */
    //3.开始在这个网络设备上循环捕获网络数据包
    if(pcap_loop(handle,10,callback,NULL)==-1){
        //handle	打开的设备句柄（来自 pcap_open_live()）
        //cnt	要捕获的包数，10 表示回调函数最多执行 10 次；-1 表示无限制（直到出错或调用 pcap_breakloop()）
        //callback	每次抓到一个数据包，就会调用这个回调函数 
        //user	传给回调函数的自定义数据（可为 NULL，也可以传结构体指针）
        //前文设置的超时时间是1000ms，意思如果在1000ms时间内到达了多个数据包 这些包都会被缓存在内核缓冲区； 到了1000ms时间，或者缓存满了，libpcap会一次性传给程序； 然后callback()会被逐个触发，每个包调用一次。
        printf("\n捕获失败");
        return 1;
    }
    

    pcap_close(handle);
    return 1;
    
}
