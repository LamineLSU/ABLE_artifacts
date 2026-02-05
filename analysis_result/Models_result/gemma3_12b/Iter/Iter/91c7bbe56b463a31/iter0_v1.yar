rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 44 24 00 56 50 68 18 93 42 00 }
        $pattern1 = { 68 18 93 42 00 68 02 00 00 80 FF 15 AC E0 42 00 }
        $pattern2 = { 6A 00 50 53 68 00 F3 40 00 53 53 53 68 00 F3 40 00 }

    condition:
        any of them
}