rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 }
        $pattern1 = { 6A 5B 0F 84 ?? ?? ?? .? ?. ?? 85 C0 0F 84 }
        $pattern2 = { E8 CE F0 FE F8 CE F0 FE }

    condition:
        any of them
}