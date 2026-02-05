rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeted exit decision checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 84 C0 74 11 FF 15 3F 18 01 00 }
        $pattern1 = { E8 27 00 00 00 8B CB FF 15 A9 16 01 00 }
        $pattern2 = { FF 15 1E 17 01 00 48 8C }

    condition:
        any of them
}