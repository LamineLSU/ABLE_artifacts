rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 CB ?? ?? ?? ?? }
        $pattern1 = { E8 C8 4A FF ?? ?? ?? ?? }
        $pattern2 = { F2 09 6A ?? ?? ?? }

    condition:
        any of them
}