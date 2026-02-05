rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific stack manipulation points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 8B ?? ?? 5A }
        $pattern1 = { 85 C0 74 07 83 C4 8B 45 ?? ?? ?? ?? }
        $pattern2 = { 0F 84 74 07 ?? ?? ?? ?? FFFF FFFE ?? }

    condition:
        any of them
}