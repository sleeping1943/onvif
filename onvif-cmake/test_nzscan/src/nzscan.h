#pragma once

#include <map>
#include <string>
#include <set>

struct DeviceInfo
{
    std::string uri;
    std::string ip;
    std::string name;
    std::string location;
    std::string hardware;

    bool operator< (const DeviceInfo& that) const
    {
        return ip < that.ip;
    }
};

#if (defined(WIN32) || defined(WIN64))
    #ifndef DLL_API 
    #define DLL_API _declspec(dllimport)
    #endif

    #ifdef __cplusplus
    extern "C" {
    #endif

        DLL_API int GetDevInfos(const std::string& user, const std::string& passwd,
                                        std::map<std::string, DeviceInfo>& rtsp_addrs, const std::string& send_ip="", int timeout=5);

        DLL_API int ScanDevIps(std::set<DeviceInfo>& dev_ips, const std::string& send_ip="", int timeout=5);

        //map<"AdapterName", "该网卡拥有的ips">
        DLL_API int GetLocalIps(std::map<std::string, std::set<std::string> >& ips);

    #ifdef __cplusplus
    }
    #endif
#else
    int GetDevInfos(const std::string& user, const std::string& passwd,
                                    std::map<std::string, DeviceInfo>& rtsp_addrs, const std::string& send_ip="", int timeout=5);

    int ScanDevIps(std::set<DeviceInfo>& dev_ips, const std::string& send_ip="", int timeout=5);

    //map<"AdapterName", "该网卡拥有的ips">
    int GetLocalIps(std::map<std::string, std::set<std::string> >& ips);
#endif
//int end_scan(Node* node);
