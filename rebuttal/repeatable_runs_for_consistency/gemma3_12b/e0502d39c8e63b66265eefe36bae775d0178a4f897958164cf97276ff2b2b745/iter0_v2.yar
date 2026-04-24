rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 51 51 E8 5A 29 01 00 FF 15 28 A2 41 00 }
        $pattern1 = { 50 53 53 53 68 00 00 00 08 53 53 53 FF 15 28 A2 41 00 }
        $pattern2 = { 68 14 A9 41 00 FF 15 38 A2 41 00 68 20 A9 41 00 50 FF 15 2C A2 41 00 85 C0 }

    condition:
        any of them
}