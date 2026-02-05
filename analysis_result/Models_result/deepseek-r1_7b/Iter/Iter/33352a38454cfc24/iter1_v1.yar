rule Bypass_Sample
{
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? 5A 30 4C ?? ?? 6D F9 FF C0 7E 00 }
        $pattern1 = { E8 ?? 5A FC 00 FB ?? FF D8 0F 04 8B ?? 85 ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? CF 3E 8B 7C ?? 8D 01 }

    condition:
        any of them
}