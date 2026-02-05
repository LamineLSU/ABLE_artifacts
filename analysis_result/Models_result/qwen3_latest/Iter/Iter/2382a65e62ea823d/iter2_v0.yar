rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF D0 5E 5D 8B E5 8B 45 08 }
        $pattern1 = { 6A 36 51 51 8D B0 ?? ?? ?? 56 56 }
        $pattern2 = { 6A 36 51 51 8D B0 ?? ?? ?? 50 50 }

    condition:
        any of them
}