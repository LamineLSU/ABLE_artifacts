rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }  // test+je+push sequence from TRACE //1
        $pattern1 = { E8 ?? ?? ?? ?? 85 C0 }  // call followed by test eax, eax
        $pattern2 = { 0F 84 ?? ?? ?? ?? }  // je with relative offset (conditional check)

    condition:
        any of them
}