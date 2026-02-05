rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? ?? ?? ?? }  // test eax, eax + je (evasion check)
        $pattern1 = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }  // call + test eax, eax + je (evasion check chain)
        $pattern2 = { FF 15 ?? ?? ?? ?? }  // call dword ptr [address] (exit decision point)

    condition:
        any of them
}