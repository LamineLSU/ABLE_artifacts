rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 04 68 00 30 00 00 68 C0 41 C8 17 6A 00 FF 15 08 50 44 00 8B F0 50 83 F8 11 74 05 }
        $pattern1 = { 55 8B EC 83 E4 F8 83 EC 48 A1 64 56 45 00 33 C4 6A 40 8D 44 24 04 6A 00 50 E8 CD D3 01 00 83 C4 0C }
        $pattern2 = { 55 8B EC 81 EC 0C 01 00 00 A1 64 56 45 00 33 C5 89 45 FC E8 38 EB 00 00 8B 0D F8 80 45 00 E8 5D FE 00 00 85 C0 }

    condition:
        any of them
}