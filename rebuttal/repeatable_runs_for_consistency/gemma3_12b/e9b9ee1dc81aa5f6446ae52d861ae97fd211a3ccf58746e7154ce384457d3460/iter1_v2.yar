rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 EC 1C 8B CC 68 38 0B 47 00 E8 6A 71 FF FF }
        $pattern1 = { 8D 4C 24 50 E8 D9 85 01 00 8B C8 E8 19 01 00 00 }
        $pattern2 = { FF 35 44 0D 47 00 FF 15 CC 72 45 00 6A 01 B8 38 44 46 00 }

    condition:
        any of them
}