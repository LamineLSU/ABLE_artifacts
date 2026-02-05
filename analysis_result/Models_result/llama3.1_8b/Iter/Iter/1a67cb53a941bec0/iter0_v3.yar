rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? ?? ?? ?? 8B CE }
        $pattern1 = { EB 34 5A 8B ?? ?? 85 C0 }
        $pattern2 = { E8 ?? ?? ?? ?? E9 B5 FC CF ?? ?? ?? ?? FF D7 }

    condition:
        any of them
}