rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific check and decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 76 84 ?? ?? ?? ?? 53 }
        $pattern1 = { 76 9C 0E FE FF AC 00 ?? }
        $pattern2 = { 5B FC 0C 0D 02 00 ?? 00 }

    condition:
        any of them
}