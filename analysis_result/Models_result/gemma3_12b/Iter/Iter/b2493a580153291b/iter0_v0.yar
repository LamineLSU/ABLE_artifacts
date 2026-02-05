rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 17 D0 00 00 }
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 }
        $pattern2 = { FF 15 8C 50 F4 00 50 FF 15 A0 50 F4 00 }

    condition:
        any of them
}