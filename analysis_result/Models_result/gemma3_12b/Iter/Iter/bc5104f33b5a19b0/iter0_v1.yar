rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 FF 15 94 30 FB 00 50 }
        $pattern1 = { 8B 40 68 C1 E8 08 A8 01 }
        $pattern2 = { 8D 84 24 1C 13 00 00 50 E8 8C 2C 02 00 }

    condition:
        any of them
}