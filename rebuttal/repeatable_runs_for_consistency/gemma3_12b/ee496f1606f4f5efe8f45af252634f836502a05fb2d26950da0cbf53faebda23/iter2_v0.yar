rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 B4 7D 42 00 50 FF 15 5C 7D 42 00 89 45 FC }
        $pattern1 = { 8B 45 08 50 6A 00 FF 15 B4 7D 42 00 50 FF 15 5C 7D 42 00 }
        $pattern2 = { 83 7D FC 00 75 08 6A 00 FF 15 88 7C 42 00 }

    condition:
        any of them
}