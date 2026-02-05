rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A }  // test+je+push+pop (first check)
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 8D 95 FC 00 00 00 }  // test+je+lea (second check)
        $pattern2 = { 8B CE E8 25 05 00 00 }  // mov ecx, esi + call (function call)

    condition:
        any of them
}