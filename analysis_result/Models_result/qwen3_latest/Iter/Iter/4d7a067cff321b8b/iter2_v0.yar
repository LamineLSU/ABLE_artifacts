rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? 6A 5B 5A }
        $pattern1 = { 8B CE E8 ?? ?? ?? ?? }
        $pattern2 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 }

    condition:
        all of them
}