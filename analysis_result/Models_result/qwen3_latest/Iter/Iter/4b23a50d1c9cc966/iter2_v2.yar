rule EvasionCheckAndExit
{
    meta:
        description = "Detects a potential evasion check followed by exit decision logic"
        cape_options = "bp0=$check_call_cmp_jump+0,action0=skip,bp1=$get_current_process_push+0,action1=skip,bp2=$terminate_process_call+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2025-04-01"

    strings:
        // Pattern 0: Call to evasion check function followed by comparison and jump
        $check_call_cmp_jump = { E8 ?? ?? ?? ?? 83 F8 01 74 20 }

        // Pattern 1: Call to GetCurrentProcess followed by push eax
        $get_current_process_push = { FF 15 ?? ?? ?? ?? 50 }

        // Pattern 2: Call to TerminateProcess
        $terminate_process_call = { FF 15 ?? ?? ?? ?? }

    condition:
        all of (
            $check_call_cmp_jump,
            $get_current_process_push,
            $terminate_process_call
        )
}