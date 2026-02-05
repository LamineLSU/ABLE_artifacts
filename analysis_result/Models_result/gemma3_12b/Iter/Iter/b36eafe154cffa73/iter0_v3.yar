rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 55 8B EC 51 C7 45 FC 00 00 00 00 6A 00 6A 40 FF 15 88 7C 42 00 }
        $pattern1 = { 85 C0 68 88 13 00 00 13 88 13 00 FF 15 88 7C 42 00 }
        $pattern2 = { 50 FF 15 2C 7D 42 00 8D 8D D4 FE FF FF 51 8D 95 D2 FE FF FF }

    condition:
        any of them
}