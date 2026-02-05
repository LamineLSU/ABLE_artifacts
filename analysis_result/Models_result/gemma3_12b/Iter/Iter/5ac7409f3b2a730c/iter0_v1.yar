rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 59 00 DE A9 D9 FF 75 08 FF 15 8C E1 DF 00 }
        $pattern1 = { 55 00 40 E7 F1 8B EC 00 40 E7 F3 FF 75 08 E8 C8 FF FF FF }
        $pattern2 = { 74 20 00 DE A9 B0 64 A1 30 00 00 00 }

    condition:
        any of them
}