#include "Windows.h"
#include "Protection/skCrypter.hpp"
#include "Kernel/Driver.hpp"
#include "Protection/XorStr.hpp"

HWND GameWindow;

auto main() -> int {

	SetConsoleTitleA(skCrypt("Usermode"));

	if (DriverCommunication->InitializeCommunication() == false)
		Sleep(2000);
		exit(0);

	DriverCommunication->InitializeCommunication();

	while (GameWindow == NULL)
		GameWindow = FindWindowA(0, _("Fortnite  "));
		Sleep(100);

	DriverCommunication->ProcessID = DriverCommunication->FindProcessWindow("FortniteClient-Win64-Shipping.exe");

	DriverCommunication->BaseAddress = DriverCommunication->GetBaseAddress();

	printf("[i] Process ID: " + DriverCommunication->ProcessID);

	printf("\n");

	printf("[i] Base Address: " + DriverCommunication->BaseAddress);

	Sleep(-1);
}