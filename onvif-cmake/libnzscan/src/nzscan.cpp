#include "wsdd.h"
#include "wsseapi.h"
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <string>

#if (defined(WIN32) || defined(WIN64))
    #pragma warning(disable:4996)
    #include <ObjBase.h>
    #include <Iphlpapi.h>
    #pragma comment(lib, "Iphlpapi.lib")
    #pragma comment(lib, "WS2_32.lib")
    #pragma comment(lib, "ole32.lib")

    #define DLL_API _declspec(dllexport)
#else //linux
    #include <ifaddrs.h>
    #include <arpa/inet.h>
	#include <unistd.h>
	#define Sleep sleep
#endif // WIN32 | WIN64

#include "nzscan.h"

using std::cout;
using std::endl;
using std::pair;
using std::vector;
using std::set;
using std::map;
using std::string;

#define GET_DEV_DETAIL(to, key, map) \
    if (map.find(#key) != map.end()) { \
        to = map[#key]; \
    }

static struct soap* ONVIF_Initsoap(struct SOAP_ENV__Header *header,
                                    const char *was_To, const char *was_Action, int timeout);

int ONVIF_ClientDiscovery();

int ONVIF_Capabilities(struct __wsdd__ProbeMatches *resp);

void UserGetProfiles(struct soap *soap, struct _tds__GetCapabilitiesResponse *capa_resp);

void UserGetUri(struct soap *soap, struct _trt__GetProfilesResponse *trt__GetProfilesResponse,
                struct _tds__GetCapabilitiesResponse *capa_resp);

void split_str(const string& prefix, string& str, map<string, string>& dev_info);

string get_ip_from_str(const string& src_str);

static int dev_count = 0;//the number of devices

static int g_timeout = 5;
static string g_user_name;
static string g_password;
static string g_send_ip;

static map<string, DeviceInfo> g_dev_infos;

const static std::string ONVIF_PREFIX = "onvif://www.onvif.org/";

//初始化soap函数
static struct soap* ONVIF_Initsoap(struct SOAP_ENV__Header *header, const char *was_To,
                                    const char *was_Action, int timeout)
{
    struct soap *soap = NULL;
    unsigned char macaddr[6];
    char _HwId[1024];
    unsigned int Flagrand;
    soap = soap_new();
    if(soap == NULL)
    {
        printf("[%d]soap = NULL\n", __LINE__);
        return NULL;
    }
    soap_set_namespaces( soap, namespaces);
    soap->recv_timeout    = 10;
    soap->send_timeout    = 10;
    soap->connect_timeout = 10;
    soap_default_SOAP_ENV__Header(soap, header);

    if (!g_send_ip.empty()) {
        struct in_addr if_req;
        inet_pton(AF_INET, g_send_ip.c_str(), (void*)&if_req.s_addr);
        soap->ipv4_multicast_if = (char*)soap_malloc(soap, sizeof(in_addr));
        memset(soap->ipv4_multicast_if, 0, sizeof(in_addr));
        memcpy(soap->ipv4_multicast_if, (char*)&if_req, sizeof(if_req));
    }

    // 为了保证每次搜索的时候MessageID都是不相同的！因为简单，直接取了随机值
    srand((int)time(0));
    Flagrand = rand()%9000 + 1000; //保证四位整数
    macaddr[0] = 0x1; macaddr[1] = 0x2; macaddr[2] = 0x3; macaddr[3] = 0x4; macaddr[4] = 0x5; macaddr[5] = 0x6;
    sprintf(_HwId,"urn:uuid:%ud68a-1dd2-11b2-a105-%02X%02X%02X%02X%02X%02X",
            Flagrand, macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
    header->wsa__MessageID =(char *)malloc( 100);
    memset(header->wsa__MessageID, 0, 100);
    strncpy(header->wsa__MessageID, _HwId, strlen(_HwId));

    if (was_Action != NULL) {
        header->wsa__Action =(char *)malloc(1024);
        memset(header->wsa__Action, '\0', 1024);
        strncpy(header->wsa__Action, was_Action, 1024);//"http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe";
    } else { }

    if (was_To != NULL) {
        header->wsa__To =(char *)malloc(1024);
        memset(header->wsa__To, '\0', 1024);
        strncpy(header->wsa__To,  was_To, 1024);//"urn:schemas-xmlsoap-org:ws:2005:04:discovery";
    }
    soap->header = header;
    return soap;
}

int ONVIF_ClientDiscovery()
{
    int retval = SOAP_FAULT;
    wsdd__ProbeType req;
    struct __wsdd__ProbeMatches resp;
    wsdd__ScopesType sScope;
    struct soap *soap = NULL;
    struct SOAP_ENV__Header header;

    const char *was_To = "urn:schemas-xmlsoap-org:ws:2005:04:discovery";
    const char *was_Action = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe";
    const char *soap_endpoint = "soap.udp://239.255.255.250:3702/";

    soap = ONVIF_Initsoap(&header, was_To, was_Action, g_timeout);
    soap->header = &header;
    soap_default_wsdd__ScopesType(soap, &sScope);
    sScope.__item = "";
    soap_default_wsdd__ProbeType(soap, &req);
    req.Scopes = &sScope;
    req.Types = "tdn:NetworkVideoTransmitter";
    
    retval = soap_send___wsdd__Probe(soap, soap_endpoint, NULL, &req);
    while (retval == SOAP_OK) {
        retval = soap_recv___wsdd__ProbeMatches(soap, &resp);//这个函数用来接受probe消息，存在resp里面
        if (retval == SOAP_OK) 
        {
            if (soap->error)
            {
                retval = soap->error;
            } else {
                dev_count++;
                if (resp.wsdd__ProbeMatches->ProbeMatch != NULL && resp.wsdd__ProbeMatches->ProbeMatch->XAddrs != NULL) {
                    DeviceInfo dev_info;
                    dev_info.ip = resp.wsdd__ProbeMatches->ProbeMatch->XAddrs;
                    dev_info.location = "";
                    map<string, string> dev_detail;
                    char* pitem = resp.wsdd__ProbeMatches->ProbeMatch->Scopes->__item;
                    if (pitem) {
                        std::string src_str(pitem);
                        split_str(ONVIF_PREFIX, src_str, dev_detail);
                        GET_DEV_DETAIL(dev_info.name, name, dev_detail);
                        GET_DEV_DETAIL(dev_info.hardware, hardware, dev_detail);
                        GET_DEV_DETAIL(dev_info.location, location, dev_detail);
                    }
                    auto ip = get_ip_from_str(resp.wsdd__ProbeMatches->ProbeMatch->XAddrs);
                    g_dev_infos[ip] = dev_info;
                    if (!g_user_name.empty() && !g_password.empty()) {
                        ONVIF_Capabilities(&resp);
                    }
                    Sleep(1);
                } else {}
            }
        } else if (soap->error) {
            if (dev_count == 0) {
                retval = soap->error;
            } else {
                retval = 0;
            }
            break;
        }
    }

    soap_destroy(soap); 
    soap_end(soap); 
    soap_free(soap);
    return retval;
}

int ONVIF_Capabilities(struct __wsdd__ProbeMatches *resp)
{
    struct _tds__GetCapabilities capa_req;
    struct _tds__GetCapabilitiesResponse capa_resp;

    struct soap *soap = NULL;
    struct SOAP_ENV__Header header;

    int retval = 0;
    soap = ONVIF_Initsoap(&header, NULL, NULL, 5);
    char *soap_endpoint = (char *)malloc(256);
    memset(soap_endpoint, '\0', 256);
    sprintf(soap_endpoint, resp->wsdd__ProbeMatches->ProbeMatch->XAddrs);
    capa_req.Category = (enum tt__CapabilityCategory *)soap_malloc(soap, sizeof(int));

    capa_req.__sizeCategory = 1;
    *(capa_req.Category) = (enum tt__CapabilityCategory)0;
    const char *soap_action = "http://www.onvif.org/ver10/device/wsdl/GetCapabilities";
    capa_resp.Capabilities = (struct tt__Capabilities*)soap_malloc(soap,sizeof(struct tt__Capabilities)) ;

    soap_wsse_add_UsernameTokenDigest(soap, "user", g_user_name.c_str(), g_password.c_str());
    do {
        int result = soap_call___tds__GetCapabilities(soap, soap_endpoint, soap_action, &capa_req, &capa_resp);
        if (soap->error) {
            retval = soap->error;
            break;
        } else {
            if (capa_resp.Capabilities == NULL) {
                printf("GetCapabilities failed! result = %d\n", result);
            } else {
                UserGetProfiles(soap, &capa_resp);
            }
        }
    }while(0);
      
    free(soap_endpoint);
    soap_endpoint = NULL;
    soap_destroy(soap);
    return retval;
}

void UserGetProfiles(struct soap *soap, struct _tds__GetCapabilitiesResponse *capa_resp)
{
    struct _trt__GetProfiles trt__GetProfiles;
    struct _trt__GetProfilesResponse trt__GetProfilesResponse;
    int result= SOAP_OK ;  
    soap_wsse_add_UsernameTokenDigest(soap,"user", g_user_name.c_str(), g_password.c_str());
    
    result = soap_call___trt__GetProfiles(soap, capa_resp->Capabilities->Media->XAddr, NULL, &trt__GetProfiles, &trt__GetProfilesResponse);
    if (result==-1)  {
        //NOTE: it may be regular if result isn't SOAP_OK.Because some attributes aren't supported by server.  
        result = soap->error;
        exit(-1);
    } else{
        if(trt__GetProfilesResponse.Profiles!=NULL)  {
            int profile_cnt = trt__GetProfilesResponse.__sizeProfiles;
            UserGetUri(soap, &trt__GetProfilesResponse, capa_resp);
        }
    }
}

void UserGetUri(struct soap *soap, struct _trt__GetProfilesResponse *trt__GetProfilesResponse,
                    struct _tds__GetCapabilitiesResponse *capa_resp)
{
    int result=0 ;
    struct _trt__GetStreamUri *trt__GetStreamUri = (struct _trt__GetStreamUri *)malloc(sizeof(struct _trt__GetStreamUri));
    struct _trt__GetStreamUriResponse *trt__GetStreamUriResponse =
        (struct _trt__GetStreamUriResponse *)malloc(sizeof(struct _trt__GetStreamUriResponse));

    trt__GetStreamUri->StreamSetup = (struct tt__StreamSetup*)soap_malloc(soap,sizeof(struct tt__StreamSetup));
    trt__GetStreamUri->StreamSetup->Stream = tt__StreamType__RTP_Unicast;
    trt__GetStreamUri->StreamSetup->Transport = (struct tt__Transport *)soap_malloc(soap, sizeof(struct tt__Transport));
    trt__GetStreamUri->StreamSetup->Transport->Protocol = tt__TransportProtocol__UDP;
    trt__GetStreamUri->StreamSetup->Transport->Tunnel = 0;
    trt__GetStreamUri->StreamSetup->__size = 1;
    trt__GetStreamUri->StreamSetup->__any = NULL;
    trt__GetStreamUri->StreamSetup->__anyAttribute =NULL;
    trt__GetStreamUri->ProfileToken = trt__GetProfilesResponse->Profiles->token;

    soap_wsse_add_UsernameTokenDigest(soap,"user", g_user_name.c_str(), g_password.c_str());
    soap_call___trt__GetStreamUri(soap, capa_resp->Capabilities->Media->XAddr, NULL, trt__GetStreamUri, trt__GetStreamUriResponse);

    if (soap->error) {
        result = soap->error;
    } else {
        auto ip = get_ip_from_str(capa_resp->Capabilities->Media->XAddr);
        auto dev_info = g_dev_infos.find(ip);
        if (dev_info != g_dev_infos.end()) {
            dev_info->second.uri = trt__GetStreamUriResponse->MediaUri->Uri;
        }
        cout << trt__GetStreamUriResponse->MediaUri->Uri << endl;
    }
}

#if (defined(WIN32) || defined(WIN64))
    DLL_API int GetDevInfos(const std::string& user, const std::string& passwd,
        std::map<std::string, DeviceInfo>& rtsp_addrs, const std::string& send_ip, int timeout)
#else
    int GetDevInfos(const std::string& user, const std::string& passwd,
        std::map<std::string, DeviceInfo>& rtsp_addrs, const std::string& send_ip, int timeout)
#endif
{
    g_user_name = user;
    g_password = passwd;
    g_send_ip = send_ip;
    g_timeout = timeout;
    g_dev_infos.clear();
    auto err_code = ONVIF_ClientDiscovery();
    rtsp_addrs = g_dev_infos;
    return err_code;
}

#if (defined(WIN32) || defined(WIN64))
    DLL_API int ScanDevIps(std::set<DeviceInfo>& dev_ips, const std::string& send_ip, int timeout)
#else
    int ScanDevIps(std::set<DeviceInfo>& dev_ips, const std::string& send_ip, int timeout)
#endif
{
    g_user_name = "";
    g_password = "";
    g_send_ip = send_ip;
    g_timeout = timeout;
    g_dev_infos.clear();
    auto err_code = ONVIF_ClientDiscovery();
    for (const auto& it : g_dev_infos) {
        dev_ips.insert(it.second);
    }
    return err_code;
}


#if (defined(WIN32) || defined(WIN64))
    DLL_API int GetLocalIps(std::map<std::string, std::set<std::string> >& ips)
#else
    int GetLocalIps(std::map<std::string, std::set<std::string> >& ips)
#endif
{
#if (defined(WIN32) || defined(WIN64))
    ULONG ulLen = 0;
    PIP_ADAPTER_INFO lpAdapterInfo = NULL, lpNextData = NULL;

    GetAdaptersInfo(lpAdapterInfo, &ulLen);
    if (0 == ulLen)
        return -1;

    lpAdapterInfo = (PIP_ADAPTER_INFO)(new CHAR[ulLen]);
    if (NULL == lpAdapterInfo)
        return -1;

    memset(lpAdapterInfo, 0, ulLen);
    ULONG uRet = GetAdaptersInfo(lpAdapterInfo, &ulLen);
    if (uRet != ERROR_SUCCESS) {
        delete [] lpAdapterInfo;
        lpAdapterInfo = NULL;
        return -1;
    }

    // multiple adapters
    for (lpNextData = lpAdapterInfo; lpNextData != NULL; lpNextData = lpNextData->Next) {
        // multiple ips for each adapter
        IP_ADDR_STRING *pIpAddrString =&(lpNextData->IpAddressList);
        int IPnumPerNetCard = 0;
        do {
            if (strcmp("0.0.0.0", pIpAddrString->IpAddress.String)) {
                ips[lpNextData->AdapterName].insert(pIpAddrString->IpAddress.String);
            }
            pIpAddrString=pIpAddrString->Next;
        } while (pIpAddrString);
    }

    delete [] lpAdapterInfo;
    lpAdapterInfo = NULL;

#else //#if (defined(WIN32) || defined(WIN64))
    struct ifaddrs *ifList  = NULL;
    int iRet = getifaddrs(&ifList);
    if (iRet < 0) { return -1; }

    struct sockaddr_in *sin = NULL;
    struct ifaddrs *ifa     = NULL;
    for (ifa = ifList; ifa != NULL; ifa = ifa->ifa_next) {
        if(ifa->ifa_addr == NULL) {
            continue;
        }
        if(ifa->ifa_addr->sa_family == AF_INET) {
            printf("\n>>> interfaceName: %s\n", ifa->ifa_name);
            sin = (struct sockaddr_in *)ifa->ifa_addr;
            printf(">>> ipAddress: %s\n", inet_ntoa(sin->sin_addr));
            ips[ifa->ifa_name].insert(inet_ntoa(sin->sin_addr));
        }
    }
    freeifaddrs(ifList);
#endif
    return 0;
}

void split_str(const string& prefix, string& str, map<string, string>& dev_info)
{
    if (str.empty()) {
        return;
    }

    // all chars are ' '
    auto start_pos = str.find_first_not_of(' ');
    if (start_pos == std::string::npos) {
        return;
    }

    try {
        std::vector<std::string> vec;
        char* src_str = const_cast<char*>(str.data());
        char* ret_str = strtok(src_str, " ");
        while (ret_str) {
            vec.push_back(ret_str);
            ret_str = strtok(NULL, " ");
        }

        for (auto& it : vec) {
            auto pos = it.find(prefix);
            if (pos != std::string::npos) {
                it = it.substr(pos + prefix.size());
                auto key_pos = it.find("/");
                if (key_pos == std::string::npos)
                    continue;
                //cout << "str:" << it << endl;
                dev_info[it.substr(0, key_pos)] = it.substr(key_pos + 1);
            }
        }
    } catch (...) {
        ;
    }
}

string get_ip_from_str(const string& src_str)
{
    std::string ip = src_str;
    std::string prefix = "http://";
    auto pos = src_str.find(prefix);
    if (pos == std::string::npos) {
        return ip;
    }

    try {
        ip = ip.substr(pos + prefix.size());
        pos = ip.find("/");
        ip = ip.substr(0, pos);
    } catch(...) {
        ;
    }
    return ip;
}
