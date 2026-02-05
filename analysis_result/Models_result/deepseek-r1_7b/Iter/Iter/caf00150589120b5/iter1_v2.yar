rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - optimized for specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { E9 B5 FC FF FF 53 6A 40 53 D8 40 11 02 01 33 C9 E8 B3 03 00 00 A1 88 85 02 01 EC 74 FA FF FF }
        $pattern2 = { E8 0D 0C 00 00 CC }

    condition:
        any of them
}