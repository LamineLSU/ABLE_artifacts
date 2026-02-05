rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 ?? ?? ?? ?? 5E }
        $pattern1 = { 8B 45 08 8B 48 14 56 6A 35 6A 00 51 }
        $pattern2 = { 8B 45 08 8B 48 14 56 }

    condition:
        any of them
}