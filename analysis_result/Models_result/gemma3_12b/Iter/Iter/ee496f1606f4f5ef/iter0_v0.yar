rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 6A 40 68 00 30 00 00 8B 45 08 50 6A 00 FF 15 B4 7D 42 00 }
        $pattern1 = { 8B FF 8B 45 FC 83 7D FC 00 75 08 6A 00 FF 15 88 7C 42 00 }
        $pattern2 = { 50 68 88 13 00 00 13 00 00 E8 F5 8B FF FF }

    condition:
        any of them
}