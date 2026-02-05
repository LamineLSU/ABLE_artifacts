rule Bypass_Sample_Evasion
{
    meta:
        description = "Evasion bypass rule - enhanced with specific patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 8B 45 F6 ?? }
        $pattern1 = { 75 ?? ?? 45 F6 ?? }
        $pattern2 = { 8B ?? ?? 45 F6 ?? }

    condition:
        any of them
}