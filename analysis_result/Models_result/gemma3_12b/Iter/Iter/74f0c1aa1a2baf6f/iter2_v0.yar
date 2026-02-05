rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { E8 ?? ?? ?? ?? 85 C0 74 13 }
        $pattern2 = { 68 ?? ?? ?? ?? FF D0 6A 01 }

    condition:
        any of them
}