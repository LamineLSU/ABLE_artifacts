rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B D9 48 83 EC 20 E8 27 00 00 00 84 C0 74 11 }
        $pattern1 = { 8B CB E8 2F 00 00 00 8B CB }
        $pattern2 = { FF 15 3F 18 01 00 }

    condition:
        any of them
}