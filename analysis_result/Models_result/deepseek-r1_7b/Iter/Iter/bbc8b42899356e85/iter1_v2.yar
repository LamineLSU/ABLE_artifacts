rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 ?? ?? 01 35 61 90 }
        $pattern1 = { E8 25 05 00 00 ?? ?? }
        $pattern2 = { E9 B5 FC FF FF ?? 35 5E 85 }

    condition:
        any of them
}