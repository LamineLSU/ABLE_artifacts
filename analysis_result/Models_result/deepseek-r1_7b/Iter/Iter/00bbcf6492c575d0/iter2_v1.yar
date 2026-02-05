rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with varied patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 74 12 }
        $pattern1 = { 85 C0 6A 5B ?? ?? ?? ?? 74 13 }
        $pattern2 = { 85 C0 74 12 ?? ?? ?? ?? ?? 0F 8C }

    condition:
        any of them
}