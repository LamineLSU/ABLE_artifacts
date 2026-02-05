rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific evasive checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 51 }  // mov edi, edi
        $pattern1 = { FF 75 08 }  // push dword ptr [ebp+08h]
        $pattern2 = { C1 E8 }  // shr eax, 08h (or similar)
    condition:
        any of them
}