rule SandboxExitCheck
{
    meta:
        description = "Detects sandbox exit check patterns"
        cape_options = "bp0=$call_1+0,action0=skip,bp1=$call_2+0,action1=skip,bp2=$jump+0,action2=skip,count=0"
        author = "Your Name"
        date = "2023-10-15"

    strings:
        $call_1 = { BB 04 01 00 00 01 D8 50 E8 ?? ?? ?? ?? }  // mov edx, 00000104h; add eax, edx; push eax; call
        $call_2 = { 53 E8 ?? ?? ?? ?? }                        // push ebx; call
        $jump = { 0F 84 ?? ?? ?? ?? }                          // je

    condition:
        all of them
}