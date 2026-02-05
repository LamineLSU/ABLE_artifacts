rule Bypass_Evasion {
    meta:
        description = "Evasion bypass patterns targeting memory address manipulation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 E8 63 EA EA EE 50 EA 8B EC EB E8 7E 32 00 CA AE FC FF 15 A0 EB 5F 5D EC 5C ED }
        $pattern1 = { E8 68 42 FB AE AC FF 15 B8 30 CA DD 00 FB 30 B8 FF 15 A0 EB 74 20 EE AE }
        $pattern2 = { 6A 00 AE AC 8B 40 68 EA FA EE C1 E8 BB A8 01 EA FF 75 08 AC }
    condition:
        (any($pattern0, $pattern1, $pattern2))
}