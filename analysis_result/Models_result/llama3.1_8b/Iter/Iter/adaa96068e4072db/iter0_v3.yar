rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { FF D0 ?? ?? ?? ?? ?? }
        $pattern2 = { 6A 36 ?? ?? ?? 8B C4 ?? }
        $pattern3 = { FF D2 ?? ?? ?? ?? ?? }

    condition:
        any of them
}