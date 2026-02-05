rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 6A 40 68 00 30 00 8B 45 08 50 6A 00 FF 15 B4 7D 42 00 }
        $pattern1 = { 85 C0 74 58 E8 4B FF FF FF 85 C0 74 58 E8 82 FF FF FF }
        $pattern2 = { FF 15 88 7C 42 00 8B 45 F0 50 8D 8D D8 FE FF FF 51 FF 15 C0 7C 42 00 }

    condition:
        any of them
}