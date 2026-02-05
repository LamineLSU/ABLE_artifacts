rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? FF C1 00 00 ?? }
        $pattern1 = { 74 ?? ?? ?? ?? ?? ?? ?? 83 C4 ?? FF C0 }
        $pattern2 = { 6D 0F 5E 8B CE E8 ?? ?? ?? ?? FF C0 ?? }

    condition:
        any of them
}