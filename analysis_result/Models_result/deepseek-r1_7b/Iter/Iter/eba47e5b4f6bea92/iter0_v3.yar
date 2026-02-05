rule EvasionBypass
{
    meta:
        description = "Evasion bypass patterns targeting memory checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 33 FD FF FF 8B CE E8 25 05 00 00 8D 95 F0 FE FF FF 03 C1 5A 5E C3 FF 15 88 A1 30 00 }
        $pattern1 = { 6A 5B 03 C3 0F 84 33 FD FF FF E8 74 FA FF FF 8B E5 03 C1 BA 21 05 21 FF 15 88 A1 B8 00 }
        $pattern2 = { 6A 40 53 E8 E5 0F 84 33 FD FF FF BE C1 03 C1 BA 21 FF 15 88 A1 D0 00 }

    condition:
        any of them
}