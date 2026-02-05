rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 FF 75 08 FF 15 B8 F0 40 00 50 FF 15 BC F0 40 00 FF 75 08 E8 4F 00 00 00 }
        $pattern1 = { 00 42 7B 0B 8B EC FF 75 08 E8 C1 FF FF FF 59 FF 75 08 FF 15 5C C2 4C 00 E8 C1 FF FF FF }
        $pattern2 = { 00 40 65 62 8B FF 55 8B EC E8 9D 21 00 00 74 20 64 A1 30 00 00 00 8B 40 68 C1 E8 A8 01 FF 75 08 }
    condition:
        any of them
}