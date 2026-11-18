#include "banapass.h"
#include "MinHook.h"

// W5P 3.00.05 (wmn5r.exe). All offsets are RVAs from the image base.
//
// The reader library is linked statically into the game executable (the exe
// does not import bngrw.dll), so every BngRw* call is hooked by address.
// In 3.00.05 the library sits 0x57EA0 bytes lower than in 3.05.00; the
// offsets below were re-derived from the 3.00.05 executable.

// No game patch here. This build follows the original OpenBanapass: the card is
// handed over inside BngRwReqWaitTouch (see oriCompat in banapass.cpp), so the
// ClearCardData() call at 0x8B17D3 is left alone. (With the old poll-thread
// delivery the card was read as invalid in 3.00.05.)

// W5P 3.00.05 Function Address Offset
#define ADDR_BngRwAttach       0xCA88C0
#define ADDR_BngRwInit         0xCA7F80
#define ADDR_BngRwFin          0xCA8010
#define ADDR_BngRwGetVersion   0xCA88B0
#define ADDR_BngRwIsCmdExec    0xCA80E0
#define ADDR_BngRwReqLed       0xCA85E0
#define ADDR_BngRwReqAction    0xCA87D0
#define ADDR_BngRwReqBeep      0xCA86D0
#define ADDR_BngRwReqCancel    0xCA8150
#define ADDR_BngRwReqSendUrlTo 0xCA8330
#define ADDR_BngRwReqWaitTouch 0xCA8220

static uintptr_t imageBase;

static int hooksOk, hooksFailed;

static void hook(const char* name, uintptr_t addr, void* detour) {
    MH_STATUS st = MH_CreateHook((void*)addr, detour, NULL);
    if (st == MH_OK) {
        hooksOk++;
        return;
    }
    hooksFailed++;
    bnLog("hook %s at +0x%lX failed: %s", name, (unsigned long)(addr - imageBase), MH_StatusToString(st));
}

static void installHooks() {
    imageBase = (uintptr_t)GetModuleHandleA(NULL);

    if (MH_Initialize() != MH_OK) {
        bnLog("MH_Initialize failed");
        return;
    }

    hook("BngRwAttach", imageBase + ADDR_BngRwAttach, (void*)BngRwAttach);
    hook("BngRwInit", imageBase + ADDR_BngRwInit, (void*)BngRwInit);
    hook("BngRwFin", imageBase + ADDR_BngRwFin, (void*)BngRwFin);
    hook("BngRwGetVersion", imageBase + ADDR_BngRwGetVersion, (void*)BngRwGetVersion);
    hook("BngRwIsCmdExec", imageBase + ADDR_BngRwIsCmdExec, (void*)BngRwIsCmdExec);
    hook("BngRwReqLed", imageBase + ADDR_BngRwReqLed, (void*)BngRwReqLed);
    hook("BngRwReqAction", imageBase + ADDR_BngRwReqAction, (void*)BngRwReqAction);
    hook("BngRwReqBeep", imageBase + ADDR_BngRwReqBeep, (void*)BngRwReqBeep);
    hook("BngRwReqCancel", imageBase + ADDR_BngRwReqCancel, (void*)BngRwReqCancel);
    hook("BngRwReqSendUrlTo", imageBase + ADDR_BngRwReqSendUrlTo, (void*)BngRwReqSendUrlTo);
    hook("BngRwReqWaitTouch", imageBase + ADDR_BngRwReqWaitTouch, (void*)BngRwReqWaitTouch);

    MH_STATUS st = MH_EnableHook(MH_ALL_HOOKS);
    if (st != MH_OK)
        bnLog("MH_EnableHook failed: %s", MH_StatusToString(st));
    else
        bnLog("hooks enabled: %d ok, %d failed", hooksOk, hooksFailed);
}

BOOL WINAPI DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        oriCompat = true;
        initBanapass();
        installHooks();
        HANDLE pollThread = CreateThread(NULL, 0, cardPollThread, NULL, 0, NULL);
        if (pollThread)
            CloseHandle(pollThread);
        else
            bnLog("CreateThread for the poll thread failed (error %lu)", (unsigned long)GetLastError());
    }
    else if (reason == DLL_PROCESS_DETACH) {
        shutdownBanapass();
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
    return TRUE;
}
