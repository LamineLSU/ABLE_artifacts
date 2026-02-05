rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? 56 FF 15 ?? ?? ?? ?? }
        $pattern1 = { 8B CE 5A E8 ?? ?? ?? ?? }
        $pattern2 = { 6A ?? 83 C4 ?? E8 ?? ?? ?? ?? }

    condition:
        any of them
}