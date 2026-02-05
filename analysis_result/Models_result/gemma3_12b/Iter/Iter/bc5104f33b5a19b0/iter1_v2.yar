rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 84 24 18 03 00 00 50 57 68 68 42 FB 00 }
        $pattern1 = { 85 C0 74 4B FF 15 94 30 FB 00 50 FF 15 B8 30 FB 00 }
        $pattern2 = { 6A 00 8D 44 24 18 50 8D 84 24 1C 13 00 00 50 }

    condition:
        any of them
}