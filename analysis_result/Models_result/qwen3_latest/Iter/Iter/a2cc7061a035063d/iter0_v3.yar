rule Malicious_Control_Flow
{
    meta:
        description = "Detects control flow hijacking via call to ExitProcess or CRT exit functions"
        cape_options = "bp0=$call_crt_exit+0,action0=skip,bp1=$call_exit_process+0,action1=skip,bp2=$prologue+0,action2=skip,count=0"
        author = "Security Researcher"
        date = "2025-03-15"

    strings:
        $call_crt_exit = { E8 ?? ?? ?? ?? 59 FF 75 08 }  // Call to __crtCorExitProcess followed by pop ecx and push [ebp+08h]
        $call_exit_process = { FF 75 08 FF 15 ?? ?? ?? ?? }  // Push [ebp+08h], then call to ExitProcess with relative address
        $prologue = { 55 8B EC FF 75 08 }  // Stack frame setup (push ebp, mov ebp, push [ebp+08h])

    condition:
        all of them
}