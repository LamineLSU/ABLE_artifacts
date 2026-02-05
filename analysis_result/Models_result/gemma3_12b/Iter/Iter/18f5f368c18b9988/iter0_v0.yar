rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 7C 58 68 10 68 26 00 FF 75 08 }
        $pattern1 = { 8D 45 F4 50 8D 45 FC 50 FF 15 B8 E3 48 00 }
        $pattern2 = { FF 15 08 E3 48 00 8D 45 F4 50 8D 45 FC 50 }

    condition:
        any of them
}