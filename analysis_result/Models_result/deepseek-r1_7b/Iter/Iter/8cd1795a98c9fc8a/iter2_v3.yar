rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 75 ?? }
        $pattern1 = { 74 ?? 8C ?? ?? 8C ?? }
        $pattern2 = { F4 FF ?? ?? ?? 6A ?? }

    condition:
        any of them
}