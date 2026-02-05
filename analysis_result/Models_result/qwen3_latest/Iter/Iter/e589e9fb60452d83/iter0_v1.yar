rule MaliciousCodeBehavior
{
    meta:
        description = "Identifies malicious code behavior through cmp, je, and call patterns"
        cape_options = "bp0=$push_call_terminate+0,action0=skip,bp1=$push_call_exit+0,action1=skip,bp2=$call_cmp_je+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"
    
    strings:
        // Pattern 0: push eax followed by call to TerminateProcess
        $push_call_terminate = { 50 FF 15 ?? ?? ?? ?? } (7 bytes)

        // Pattern 1: push [ebp+08h] followed by call to ExitProcess
        $push_call_exit = { FF 75 08 FF 15 ?? ?? ?? ?? } (9 bytes)

        // Pattern 2: call to unknown function, cmp eax, 0x01, and je
        $call_cmp_je = { E8 36 34 01 00 83 F8 01 74 20 } (10 bytes)

    condition:
        all of them
}