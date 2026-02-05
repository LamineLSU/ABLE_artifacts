rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { 50 E8 E3 FA E9 B5 FC FF FF FF 33 DB BA 21 05 00 00 53 6A 40 53 68 40 11 35 01 }
        $pattern2 = { 50 FF 15 88 A0 35 01 50 FF 15 2C A1 35 01 33 FF 8B 4D FC 5F 5E 33 CD 5B E8 57 26 00 00 }

    condition:
        any of them
}