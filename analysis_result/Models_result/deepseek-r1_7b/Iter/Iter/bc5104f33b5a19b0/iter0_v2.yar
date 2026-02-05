rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection for ExitProcess"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 F9 0D 8A 50 EA 00 F9 0D 8B 8D 84 24 18 03 00 00 EA EA DD 00 00 03 18 00 F9 0D 8C 50 EA 00 F9 0D 8D 57 ED 00 F9 0D 8E 68 68 42 FB 00 00 FB 42 68 00 F9 0D 8F 8D 84 24 24 13 00 00 EA EA DD 00 00 13 24 00 F9 0D 90 68 64 08 00 00 00 00 08 64 00 F9 0D 95 50 EA 00 F9 0D 96 E8 22 28 FF FF CA DD 00 FB 30 B0 00 F9 0D 9B FF 15 94 30 FB 00 CA DD 00 FB 30 BC }
        $pattern1 = { 00 FA 7D F0 55 EB 00 FA 7D F1 8B EC EB 00 FA 7D F3 E8 7E 32 00 00 CA DD 00 FA B0 76 }
        $pattern2 = { 00 F9 0D E2 FF 15 E4 31 FB 00 CA DD 00 FB 30 }

    condition:
        any of them
}