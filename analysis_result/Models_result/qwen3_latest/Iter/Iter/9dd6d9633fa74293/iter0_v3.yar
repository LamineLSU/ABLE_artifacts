rule FunctionExitPatterns
{
    meta:
        description = "Captures function prologue and exit call patterns observed in the code"
        cape_options = "bp0=$prologue_exit1+0,action0=skip,bp1=$push_call_exit2+0,action1=skip,bp2=$push_call_pop3+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-01"
    
    strings:
        // Pattern 1: Function prologue + early exit call (___crtCorExitProcess)
        $prologue_exit1 = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? } (12 bytes)
        
        // Pattern 2: Push [ebp+08h] + call to ExitProcess (KERNEL32)
        $push_call_exit2 = { FF 75 08 FF 15 ?? ?? ?? ?? } (8 bytes)
        
        // Pattern 3: Push [ebp+08h] + call + pop ecx (intermediate exit call)
        $push_call_pop3 = { FF 75 08 E8 ?? ?? ?? ?? 59 } (8 bytes)
    
    condition:
        any of ($prologue_exit1, $push_call_exit2, $push_call_pop3)
}