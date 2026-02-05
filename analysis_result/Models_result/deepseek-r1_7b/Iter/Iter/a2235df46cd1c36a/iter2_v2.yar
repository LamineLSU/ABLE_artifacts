rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - specific call patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 25 ?? ?? ?? ?? }
        $pattern1 = { FC F8 CE ?? ?? ?? ?? 74 0C }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }

    condition:
        any of them
}