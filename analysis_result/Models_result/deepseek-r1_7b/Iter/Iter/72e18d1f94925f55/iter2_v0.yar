rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved to target earlier decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 9B 65 2B 8B FF ED ED 00 9B 65 2D 55 EB 00 9B 65 2E 8B EC EB 00 9B 65 30 E8 CD 3D 00 00 CA 00 9B A3 02 00 9B 65 35 74 20 00 9B 65 5A 00 9B 65 38 C1 E8 08 EA 08 AE 00 9B 65 3A FF 75 08 DD EB 08 00 9B 65 42 E8 BF 31 E7 04 CA 04 F9 03 C4 00 9B 65 46 A8 01 EA 01 00 9B 65 48 75 10 00 9B 65 5A AE 00 9B 65 5C C1 E8 08 EA 08 00 9B 65 5D A8 01 EA 01 00 9B 65 5F 75 10 00 9B 65 6A 00 9B 65 62 FF 75 08 DD EB 08 00 9B 65 63 E8 BF 31 E7 04 CA 04 F9 03 C4 }
    condition:
        any of them
}