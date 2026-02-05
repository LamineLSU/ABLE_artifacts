rule MalwareExitCheck
{
    meta:
        description = "Detects exit logic in a malicious binary that includes checks for termination."
        cape_options = "bp0=$call1+0,action0=skip,bp1=$call2+0,action1=skip,bp2=$pop+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"
    
    strings:
        // First call to a potential exit function (e.g., __crtCorExitProcess)
        $call1 = { FF 75 08 E8 ?? ?? ?? ?? }  // push [ebp+08h] followed by call (5 bytes offset)

        // Second call to another exit function (e.g., ExitProcess)
        $call2 = { FF 75 08 FF 15 ?? ?? ?? ?? }  // push [ebp+08h] followed by call (5 bytes offset)

        // Pop ecx before the second call (contextual indicator)
        $pop = { 59 FF 15 ?? ?? ?? ?? }  // pop ecx followed by call (5 bytes offset)

    condition:
        any of ($call1, $call2, $pop)
}