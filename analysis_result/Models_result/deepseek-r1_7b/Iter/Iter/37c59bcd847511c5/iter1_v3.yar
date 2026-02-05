rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 4D FC E9 B5 FC FF FF }
        $pattern1 = { 0F 84 33 FD FF FF 00 9A 5E 83 }
        $pattern2 = { E8 25 05 00 00 8B 4D FC E9 B5 FC FF FF }

    condition:
        any of them
}