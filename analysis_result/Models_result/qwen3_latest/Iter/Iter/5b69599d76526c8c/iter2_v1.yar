rule MaliciousCodePattern
{
    meta:
        description = "Detects suspicious code sequences associated with malicious behavior."
        cape_options = "bp0=$call_exitprocess+0,action0=skip,bp1=$call_rtlfreeheap+0,action1=skip,bp2=$call_unknown_function+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2025-04-01"

    strings:
        // Pattern 1: Call to ExitProcess with surrounding instructions
        $call_exitprocess = { 52 68 75 86 5E 5D C3 }

        // Pattern 2: Call to RtlFreeHeap with surrounding instructions
        $call_rtlfreeheap = { 50 51 00 00 00 00 00 00 5E 5D C3 }

        // Pattern 3: Call to 0x0000000000000000 (e.g., 0x0000000000000000) with preceding instruction
        $call_unknown_function = { 8B 44 24 04 E8 24 13 00 00 }

    condition:
        any of ($call_exitprocess, $call_rtlfreeheap, $call_unknown_function)
}