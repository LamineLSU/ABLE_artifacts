rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - refined based on trace analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 8B }
        $pattern1 = { 75 ?? ?? ?? ?? 83 C4 }
        $pattern2 = { 6A ?? ?? ?? ?? 8B }

    condition:
        any of them
}