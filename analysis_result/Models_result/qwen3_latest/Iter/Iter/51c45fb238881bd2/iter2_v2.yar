rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 85 ?? ?? ?? ?? }  // test eax, eax + jne (evasion check)
        $pattern1 = { 83 7D E8 14 0F 82 ?? ?? ?? ?? }  // cmp dword + jc (evasion check)
        $pattern2 = { FF 96 ?? ?? ?? ?? }  // call dword ptr [esi+offset] (exit trigger)

    condition:
        any of them
}