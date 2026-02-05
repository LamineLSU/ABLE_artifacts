rule Bypass_Sample
{
    meta:
        description = "Evasion bypass using multiple instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B EE 33 DB BA 04 01 00 00 5A 8B CE E8 25 05 00 00 CA 00 00 01 10 EA 89 9D F0 FE FF FF 00 00 01 10 0F 84 33 FD FF FF 53 5A 00 00 01 04 E8 E3 FA FF FF CA 00 00 05 21 74 07 50 FF 15 88 A0 A4 00 CA 00 A1 2C }
        $pattern1 = { 6A 5B EE 33 DB BA 04 01 00 00 8B CE E8 74 FA FF FF CA 00 00 01 10 EA 89 9D F0 FE FF FF 00 00 01 10 0F 84 33 FD FF FF 5A 6A 40 E8 E3 FA FF FF CA 00 00 05 21 74 07 50 FF 15 88 A0 A4 00 CA 00 A5 E8 }
        $pattern2 = { 6A 5B EE 33 DB BA 04 01 00 00 8B CE E8 74 FA FF FF CA 00 00 01 10 EA 89 9D F0 FE FF FF 00 00 01 10 0F 84 33 FD FF FF 6A 40 E8 E3 FA FF FF CA 00 00 05 21 74 07 50 FF 15 88 A0 A4 00 CA 00 A5 E8 }
    condition:
        any of them
}