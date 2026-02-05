rule EvasionBypass
{
    meta:
        description = "Evasion bypass detection for critical call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 ?? ?? 05 ?? ?? 8A 4F }
        $pattern1 = { E8 ?? ?? ?? ?? 0F C0 6A ?? }
        $pattern2 = { FF ?? ?? ?? ?? ?? 3D 74 ?? 3F }

    condition:
        any of them
}