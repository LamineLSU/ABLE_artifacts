rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 CC 72 45 00 6A 01 50 50 }
        $pattern1 = { FF 15 7C 72 45 00 8B CE E8 0B FF FF FF }
        $pattern2 = { FF 15 7C 72 45 00 EB 36 6A 00 FF 15 84 72 45 00 }

    condition:
        any of them
}