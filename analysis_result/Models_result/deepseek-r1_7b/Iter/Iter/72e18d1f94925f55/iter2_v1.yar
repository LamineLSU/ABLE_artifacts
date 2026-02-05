rule Bypass_Sample_Evasion
{
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 1A ?? ?? ?? ?? E8 95 DB ?? 43 74 }
        $pattern1 = { 6A 5A 8B CE E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 0F 84 ?? ?? ?? ?? 8B 45 ?? }

    condition:
        any of them
}