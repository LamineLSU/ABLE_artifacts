rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? 8B 4D F8 83 F8 01 }  // test eax, eax + je + mov + cmp
        $pattern1 = { FF 15 ?? ?? ?? ?? }              // call to ExitProcess (wildcarded address)
        $pattern2 = { 85 C0 74 07 8B 4D F8 83 F8 00 }  // test eax, eax + je + mov + cmp

    condition:
        any of them
}