rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 A8 01 75 10 }
        $pattern1 = { FF 75 08 E8 0B 00 00 00 59 FF 75 08 FF 15 8C E1 F6 00 }
        $pattern2 = { 8B FF 55 8B EC E8 07 26 00 00 83 F8 01 74 20 FF 75 08 }

    condition:
        any of them
}