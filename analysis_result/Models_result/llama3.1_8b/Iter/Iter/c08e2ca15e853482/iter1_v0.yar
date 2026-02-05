rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 04 68 00 30 00 00 68 C0 41 C8 17 6A 00 FF 15 08 50 44 00 8B F0 50 83 F8 11 74 05 8B C0 FC 85 C9 }
        $pattern1 = { 55 8B EC 83 E4 F8 A1 64 56 45 00 33 C4 89 44 24 44 6A 40 8D 44 24 04 }
        $pattern2 = { DC 8B 45 FC 5A 0F B6 CB 5A 0F B6 54 CC }

    condition:
        any of them
}