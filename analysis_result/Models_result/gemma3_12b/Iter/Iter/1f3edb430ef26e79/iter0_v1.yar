rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? 50 8B 45 ?? }
        $pattern1 = { 51 8B 45 ?? 8B 45 ?? }
        $pattern2 = { 8B 45 ?? 52 8B 4D ?? }

    condition:
        any of them
}