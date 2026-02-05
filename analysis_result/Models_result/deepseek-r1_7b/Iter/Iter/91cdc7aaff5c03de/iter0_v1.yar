rule Bypass_Sample
{
    meta:
        description = "Evasion bypass after function call"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 7E 07 5D ?? ?? ?? ?? 83 F8 20 5E 07 }
        $pattern2 = { 83 F4 20 5F 07 7E 07 5D ?? ?? ?? ?? 83 F8 20 5E 07 }

    condition:
        any of them
}