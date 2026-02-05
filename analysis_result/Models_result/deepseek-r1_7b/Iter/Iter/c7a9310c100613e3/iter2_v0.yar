rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeted conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 E8 03 00 00 ?? 00 00 ?? 00 00 ?? FF 35 34 51 A1 03 ?? }
        $pattern1 = { 50 ?? 00 00 ?? 00 00 00 00 00 00 C4 50 A1 03 ?? }
        $pattern2 = { 68 E8 03 00 00 ?? 00 00 ?? 00 00 ?? FF 7C 51 A1 03 ?? }
    condition:
        any of them
}