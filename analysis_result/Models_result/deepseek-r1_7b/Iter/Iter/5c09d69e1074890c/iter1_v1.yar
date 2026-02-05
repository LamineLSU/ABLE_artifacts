rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 C4 }
        $pattern1 = { 75 ?? 8A ?? ?? }
        $pattern2 = { 8B 45 8D ?? ?? ?? }

    condition:
        any of them
}