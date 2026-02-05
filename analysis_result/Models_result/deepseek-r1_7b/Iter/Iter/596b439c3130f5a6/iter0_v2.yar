rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection using multiple context points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? }
        $pattern1 = { 74 ?? ?? ?? E8 0F C9 ?? }
        $pattern2 = { 6A ?? 5A 45 ?? E8 ?? ?? ?? }

    condition:
        any of them
}