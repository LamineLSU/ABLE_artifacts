rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting early decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 43 1C 00 00 74 0E E8 E0 A2 FF FF }
        $pattern1 = { E8 EE 82 FF FF 0F 84 ?? }
        $pattern2 = { E8 B7 F7 FF FF CA }

    condition:
        (match $pattern0) || 
        (match $pattern1) ||
        (match $pattern2)
}