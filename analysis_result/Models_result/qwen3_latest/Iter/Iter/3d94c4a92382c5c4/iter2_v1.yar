rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 85 ?? ?? ?? ?? }  // test eax, eax + jne (WaitForSingleObject check)
        $pattern1 = { 83 FE 1A 0F 8C ?? ?? ?? ?? }  // cmp esi, 1Ah + jl (loop limit check)
        $pattern2 = { FF 35 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }  // push + call WaitForSingleObject

    condition:
        any of them
}