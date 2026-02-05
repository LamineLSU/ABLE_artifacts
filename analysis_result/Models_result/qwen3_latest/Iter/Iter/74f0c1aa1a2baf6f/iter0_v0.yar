rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 8B C8 8A 01 }  // Call GetCommandLineA + mov ecx, eax + mov al
        $pattern1 = { 8A 01 3C 22 75 ?? }                // Check for quote in command line
        $pattern2 = { 56 FF 15 ?? ?? ?? ?? }            // Push esi + call ExitProcess

    condition:
        any of them
}