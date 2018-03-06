#ifndef __MEM_ATTACKER_CONSOLE_H__
#define __MEM_ATTACKER_CONSOLE_H__

#include "payload_stack_overflow.h"
#include "payload_use_after_free.h"

#include "..\..\utils\drivers_launch_pad.h" // DriversLaunchPad
#include "..\..\utils\print_messages.h"
#include "..\shared\mem_attacker_shared.h" // IOCTL-codes

namespace mem_attacker_console {

	class MemAttacker : public drivers_launch_pad::DriversLaunchPad
	{
	public:

		/*  */
		bool read_1byte(ULONG64 addr);

		/*  */
		bool write_1byte(ULONG64 addr, char value);

		/*  */
		bool write_8bytes(ULONG64 addr, ULONG64 value);

		//////////////////////////////////////////////////////////////////////////

		/*  */
		bool hide_proc(ULONG64 procId);

		/*  */
		bool set_priv(ULONG64 procId);

		/* Run stack overflow without any payload to calculate the required buffer size */
		bool run_simple_stack_overflow(DWORD bufferSz);

		/* Run stack overflow with the payload to escalate process privileges */
		bool run_stack_overflow_with_payload(DWORD targetPid);

		/* Run a simple use-after-free exploit*/
		bool run_use_after_free();

		/* Run a use-after-free exploit with the payload to escalate process privileges */
		bool run_use_after_free_with_payload(const DWORD targetPid);

		/* Test pool allocations */
		void test_pool_allocations();

		/* run pool overflow */
		bool run_pool_overflow(DWORD bufferSz);
	};

}



#endif // ifndef __MEM_ATTACKER_CONSOLE_H__
