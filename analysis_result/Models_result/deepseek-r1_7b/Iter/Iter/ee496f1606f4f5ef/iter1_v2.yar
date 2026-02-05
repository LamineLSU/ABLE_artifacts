rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific calls for exit checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC FF 15 5C 7D 42 00 89 45 FC 83 7D FC 00 75 08 }
        $pattern1 = { E8 74 FE FF FF E8 F5 8B FF FF FF 74 03 75 }
        $pattern2 = { B8 E8 04 95 FF FF 74 03 75 }

    condition:
        (match $pattern0) || (match $pattern1) || (match $pattern2)
}