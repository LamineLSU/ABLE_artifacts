rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 85 ?? ?? ?? ?? }  // test eax, eax + jne (from TRACE //1)
        $pattern1 = { FF 96 ?? ?? ?? ?? }         // call dword ptr [esi+000000B0h] (from TRACE //1)
        $pattern2 = { 83 7D E8 14 0F 82 ?? ?? ?? ?? }  // cmp dword ptr [ebp-18h], 14h + jc (from TRACE //1)

    condition:
        any of them
}