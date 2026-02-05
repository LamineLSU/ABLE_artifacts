rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 66 81 3C 24 E4 07 73 07 }  // cmp word [esp], 07E4h + jnc
        $pattern1 = { 54 E8 ?? ?? ?? ?? }        // push esp + call (ExitProcess)
        $pattern2 = { 8B D8 54 E8 B0 C8 F9 FF }  // mov ebx, eax + push esp + call GetSystemTime

    condition:
        any of them
}