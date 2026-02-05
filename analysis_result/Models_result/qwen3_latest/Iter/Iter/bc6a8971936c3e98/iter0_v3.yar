rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? 85 C0 75 ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 8B 4D ?? }
        $pattern2 = { 75 07 8B 45 ?? }

    condition:
        any of them
}