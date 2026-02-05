rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 82 3D 01 00 53 56 57 33 F6 56 56 56 68 14 80 43 00 FF 15 00 50 43 00 }
        $pattern1 = { 50 FF 15 E0 74 44 00 6A 3C 8D 85 EC FE FF FF 5B 89 85 A8 FE FF FF 89 9D 94 FE FF FF }
        $pattern2 = { 53 56 57 33 DB 53 6A 40 BE 00 30 00 00 56 68 D0 07 00 00 53 FF 15 5C 75 44 00 50 FF 15 14 75 44 00 85 C0 75 07 }

    condition:
        any of them
}