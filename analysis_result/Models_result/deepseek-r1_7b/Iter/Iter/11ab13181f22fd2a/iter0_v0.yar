rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 05 00 }
        $pattern1 = { 74 ?? ?? ?? ?? .? ?. }
        $pattern2 = { FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}