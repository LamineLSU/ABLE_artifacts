rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 48 83 EC 20 8B D9 E8 27 00 00 00 84 C0 74 11 }
        $pattern1 = { 8B D9 E8 27 00 00 00 84 C0 FF 15 A9 16 01 00 48 8B C8 }
        $pattern2 = { FF 15 3F 18 01 00 E8 12 00 00 00 83 C4 08 53 }

    condition:
        any of them
}