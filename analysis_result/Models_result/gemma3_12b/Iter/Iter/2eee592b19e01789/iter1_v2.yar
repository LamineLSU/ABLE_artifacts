rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 48 83 EC 20 8B D9 E8 27 00 00 00 }
        $pattern1 = { 53 74 11 FF 15 A9 16 01 00 48 8B C8 }
        $pattern2 = { 83 F8 01 74 12 8B 4D F8 }

    condition:
        any of them
}