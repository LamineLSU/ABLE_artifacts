rule MalwareEvasionCheck
{
    meta:
        description = "Detects evasion checks in malware by bypassing conditional jumps and exit calls"
        cape_options = "bp0=$call_exitprocess+0,action0=skip,bp1=$call_rtl+0,action1=skip,bp2=$test_jump+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2023-10-05"

    strings:
        // Pattern 1: Bypass ExitProcess call by skipping the call instruction
        $call_exitprocess = { 5E 5D 52 FF D0 }  // pop esi, pop ebp, push edx, call eax

        // Pattern 2: Bypass RtlExitThread call by skipping the call instruction
        $call_rtl = { 8B 06 FF D0 }  // mov eax, [esi], call eax

        // Pattern 3: Bypass conditional jump based on test eax, eax
        $test_jump = { 85 C0 0F 84 ?? ?? ?? ?? }  // test eax, eax, je [offset]

    condition:
        all of (
            $call_exitprocess,
            $call_rtl,
            $test_jump
        )
}