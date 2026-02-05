rule ControlFlowPatterns
{
    meta:
        description = "Detects control flow patterns leading to ExitProcess and CloseHandle calls"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"
    strings:
        // Pattern 1: Test EAX followed by a conditional jump (JE)
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }

        // Pattern 2: Push EBX followed by a call to ExitProcess
        $pattern2 = { 53 FF 15 ?? ?? ?? ?? }

        // Pattern 3: Push EAX followed by a call to CloseHandle
        $pattern3 = { 50 FF 15 ?? ?? ?? ?? }

    condition:
        all of ($pattern1 or $pattern2 or $pattern3)
}