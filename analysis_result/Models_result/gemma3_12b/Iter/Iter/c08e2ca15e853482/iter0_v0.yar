rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 04 68 00 30 00 00 68 C0 41 C8 17 }
        $pattern1 = { 5E 5B 68 00 80 00 00 68 C0 41 C8 17 }
        $pattern2 = { FF 15 44 84 45 00 6A 3C 8D 85 94 FE FF FF }

    condition:
        any of them
}