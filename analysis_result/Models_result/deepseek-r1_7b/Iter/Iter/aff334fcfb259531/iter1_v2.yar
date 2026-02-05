rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - Counterfeit Pattern Analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 ?? 8A ?? ?? ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { FF FC AC 33 C9 0A 04 53 ED }

    condition:
        any of them
}