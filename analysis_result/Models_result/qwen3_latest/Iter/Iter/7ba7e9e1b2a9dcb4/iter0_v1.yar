rule MemoryPattern
{
    meta:
        description = "Detects three distinct memory patterns from the trace"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        // Pattern 0: Test EAX, EAX followed by JZ
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }

        // Pattern 1: Push EAX followed by Call (ExitProcess)
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? }

        // Pattern 2: Call (CloseHandle) with preceding Push EBX
        $pattern2 = { 53 FF 15 ?? ?? ?? ?? }

    condition:
        all of them
}