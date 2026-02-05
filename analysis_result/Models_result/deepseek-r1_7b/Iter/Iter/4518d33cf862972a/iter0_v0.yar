rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting stack displacement"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 8B 45 FF 15 00 50 E9 00 ?? ?? ?? ?? }
        $pattern1 = { E8 C5 74 1A 80 ?? ?? ?? ?? ?? ?? ?? }
        $pattern2 = { 6A 5A 8B CE E8 ?? ?? ?? ?? 8B 45 }

    condition:
        any of them
}