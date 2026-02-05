rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 C4 F0 8B ?? ?? 54 E8 ?? ?? ?? ?? ?? }
        $pattern1 = { 0F 94 C0 8B ?? ?? 6A 00 E8 ?? ?? ?? ?? ?? }
        $pattern2 = { 6A 00 E8 ?? ?? ?? ?? 8B C3 83 C4 10 }

    condition:
        any of them
}