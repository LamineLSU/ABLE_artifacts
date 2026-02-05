rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting memory check evictions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { 83 F8 01 74 8B 4D F8 ?? ?? ?? ?? ?? }
        $pattern2 = { 8B 4D F8 E5 FC FF ?? ?? ?? ?? ?? ?? }

    condition:
        any of them
}