#ifndef COMMON_H
#define COMMON_H

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <commctrl.h>
#include <richedit.h>
#include <tlhelp32.h>
#pragma comment(lib, "comctl32.lib")

#define IDC_PID_INPUT          101
#define IDC_BTN_INJECT         102
#define IDC_LOG_EDIT           103
#define IDC_PROCESS_NAME_INPUT 104
#define IDC_BTN_INJECT_ALL     105
#define WM_ADD_LOG_ENTRY (WM_USER + 100)

#endif