rule MaliciousExitProcess
{
    meta:
        description = "Detects malicious use of ExitProcess via indirect calls"
        cape_options = "bp0=$call1+0,action0=skip,bp1=$call2+0,action1=skip,bp2=$setup+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2023-10-15"

    strings:
        // Pattern 1: Push ebp+08h followed by call with offset
        $call1 = { FF 75 08 E8 ?? ?? ?? ?? }

        // Pattern 2: Pop ecx, push ebp+08h, followed by call with displacement
        $call2 = { 59 FF 75 08 FF 15 ?? ?? ?? ?? }

        // Pattern 3: Full setup before first call (mov edi, push ebp, mov ebp, push ebp+08h)
        $setup = { 8B FF 55 8B EC FF 75 08 }

    condition:
        all of (
            $call1 or $call2 or $setup
        )
}