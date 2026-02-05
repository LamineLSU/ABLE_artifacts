rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 33 C9 E8 ?? ?? ?? ?? }  // xor ecx, ecx + call (debugger check)
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? }   // push eax + call CloseHandle (sandbox handle check)
        $pattern2 = { 85 C0 0F 84 ?? ?? ?? ?? } // test eax, eax + conditional jump (sandbox detection)

    condition:
        any of them
}