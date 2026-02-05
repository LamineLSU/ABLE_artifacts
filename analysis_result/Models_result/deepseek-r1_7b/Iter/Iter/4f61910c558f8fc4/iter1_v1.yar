rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rules targeting exit paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 ?? ?? ?? ?? ?? ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 85 C0 ?? ?? ?? ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}