rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 94 30 FB 00 85 C0 74 4B }
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 }
        $pattern2 = { 8D 44 24 18 50 8D 84 24 1C 13 00 00 }

    condition:
        any of them
}