/*
 * =====================================================================================
 *
 *    Filename:  main.c
 *    Description:  简单例程测试:客户端通过ONVIF协议搜索前端设备
 *
 * =====================================================================================
 */
#include "nzscan.h"
#include <iostream>
#include <iomanip>

using std::cout;
using std::endl;
using std::set;
using std::map;
using std::string;


int main(void )
{
#if 0
    printf("******************local ips*****************************\n");
    map<string, set<string> > local_ips;
    GetLocalIps(local_ips);
    for (const auto& it : local_ips) {
        for (const auto& ip : it.second) {
            printf("%s:%s\n", it.first.c_str(), ip.c_str());
            printf("Boardcast with addr[%s]\n", ip.c_str());
            printf("\n******************ips*****************************\n");
            set<string> addrs;
            //ScanDevIps(addrs, ip, 5);
            for (const auto& it : addrs) {
                printf("%s\n", it.c_str());
            }
            printf("\n******************rtsps*****************************\n");
            map<string, DeviceInfo> rtsps;
            GetDevInfos("admin", "admin123", rtsps, ip, 5);
            for (const auto& it : rtsps) {
                printf("%s\n", it.second.uri.c_str());
            }
        }
    }
#else
    map<string, DeviceInfo> rtsps;
    GetDevInfos("admin", "admin123", rtsps, "192.168.2.77", 5);

    printf("\n******************rtsps*****************************\n");
    for (const auto& it : rtsps) {
        cout << std::setw(10) << "ip:" << it.second.ip << endl;
        cout << std::setw(10) << "uri:" << it.second.uri << endl;
        cout << std::setw(10) << "name:" << it.second.name << endl;
        cout << std::setw(10) << "location:" << it.second.location << endl;
        cout << std::setw(10) << "hardware:" << it.second.hardware << endl;
        cout << "\n****************************************************\n" << endl;
    }
#endif 
    printf("Press any key to exit...\n");
    getchar();
	return 0;
}
