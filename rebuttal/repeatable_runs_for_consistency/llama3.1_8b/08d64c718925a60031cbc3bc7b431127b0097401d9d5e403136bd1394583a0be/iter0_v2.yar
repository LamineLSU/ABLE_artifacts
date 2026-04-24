rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 D8 54 41 00 FF 75 08 6A 00 FF 75 08 }
        $pattern1 = { 68 00 C2 41 00 6A 02 FF 15 28 54 41 00 6A 00 }
        $pattern2 = { FF 35 F0 C1 41 00 FF 15 D4 54 41 00 EB 38 }

    condition:
        any of them
}