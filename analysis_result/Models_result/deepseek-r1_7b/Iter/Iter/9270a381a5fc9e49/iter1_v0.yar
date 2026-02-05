rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - using specific hex sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 14 ?? ?? ?? ?? ?? }
        $pattern1 = { 8D B0 98 0C 00 00 ?? ?? ?? ?? ?? ?? }
        $pattern2 = { ?? ?? ?? ?? 56 ?? ?? ?? ?? 8B 4D 0C }

    condition:
        any of them
}