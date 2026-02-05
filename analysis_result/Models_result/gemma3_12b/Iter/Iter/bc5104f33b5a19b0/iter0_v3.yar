rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 8D 44 24 18 50 8D 84 24 1C 13 00 00 50 E8 8C 2C 02 00 59 50 8D 84 24 20 13 00 00 50 6A F4 FF 15 40 30 FB 00 50 FF 15 BC 30 FB 00 }
        $pattern1 = { 8B FF 55 8B EC E8 7E 32 00 00 84 C0 74 20 64 A1 30 00 00 00 }
        $pattern2 = { 50 8D 84 24 18 03 00 00 50 57 68 68 42 FB 00 8D 84 24 24 13 00 00 68 64 08 00 00 50 E8 22 28 FF FF }

    condition:
        any of them
}