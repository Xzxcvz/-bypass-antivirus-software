/* 
 * upnpc — minimal UPnP port mapper (uses Windows NATUPnP COM)
 * Usage: upnpc <local_port> <protocol>
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <objbase.h>
#include <stdio.h>
#include <natupnp.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "hnetcfg.lib")
#pragma comment(lib, "ws2_32.lib")

static DWORD get_local_ip(void) {
    WSADATA wd;
    WSAStartup(MAKEWORD(2,2), &wd);
    char hn[256]; gethostname(hn, sizeof(hn));
    struct addrinfo *ai = NULL, hints = {0};
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    DWORD ip = 0;
    if (getaddrinfo(hn, NULL, &hints, &ai) == 0) {
        ip = ((struct sockaddr_in*)ai->ai_addr)->sin_addr.s_addr;
        freeaddrinfo(ai);
    }
    WSACleanup();
    return ip;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: upnpc <port> [TCP|UDP]\n"); return 1;
    }
    LONG port = atol(argv[1]);
    const char *proto_s = (argc > 2) ? argv[2] : "TCP";

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    IUPnPNAT *pNAT = NULL;
    HRESULT hr = CoCreateInstance(&CLSID_UPnPNAT, NULL, CLSCTX_ALL,
                                  &IID_IUPnPNAT, (void**)&pNAT);
    if FAILED(hr) {
        printf("[-] CoCreateInstance UPnPNAT failed: 0x%08X\n", hr);
        printf("    UPnP may not be available\n");
        CoUninitialize(); return 1;
    }
    IStaticPortMappingCollection *pColl = NULL;
    hr = IUPnPNAT_get_StaticPortMappingCollection(pNAT, &pColl);
    if (FAILED(hr) || !pColl) {
        printf("[-] No UPnP port mapping collection\n");
        printf("    Router may not support UPnP or it's disabled\n");
        pNAT->lpVtbl->Release(pNAT);
        CoUninitialize(); return 1;
    }
    DWORD lip = get_local_ip();
    struct in_addr ia; ia.s_addr = lip;
    char *ip_str = inet_ntoa(ia);
    if (!ip_str) ip_str = "0.0.0.0";

    BSTR bProto = SysAllocString(proto_s[0]=='T'?L"TCP":L"UDP");
    BSTR bDesc  = SysAllocString(L"WindowsUpdate");
    BSTR bLocal = SysAllocStringLen(NULL, 16);
    wsprintfW(bLocal, L"%S", ip_str);

    IStaticPortMapping *pMap = NULL;
    hr = IStaticPortMappingCollection_Add(pColl, port, bProto, port, bLocal, VARIANT_TRUE, bDesc, &pMap);
    if FAILED(hr) {
        printf("[-] AddPortMapping failed: 0x%08X\n", hr);
    } else {
        printf("[+] UPnP OK! External %d/%s → %s:%d\n", port, proto_s, ip_str, port);
        pMap->lpVtbl->Release(pMap);
    }
    SysFreeString(bProto); SysFreeString(bDesc); SysFreeString(bLocal);
    pColl->lpVtbl->Release(pColl);
    pNAT->lpVtbl->Release(pNAT);
    CoUninitialize();
    return 0;
}
