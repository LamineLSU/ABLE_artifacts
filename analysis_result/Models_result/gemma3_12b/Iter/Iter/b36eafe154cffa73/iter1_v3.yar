rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 08 8B 45 FC 83 7D FC 00 }
        $pattern1 = { 6A 00 5A 8B CE E8 ?? ?? ?? ?? }
        $pattern2 = { 68 00 30 00 00 8B 45 08 50 6A 00 }

    condition:
        any of them
}