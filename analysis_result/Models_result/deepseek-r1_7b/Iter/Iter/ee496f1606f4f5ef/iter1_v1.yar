rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting multiple paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 75 C1 A3 8D 4A 8B ?? ?? ?? ?? }
        $pattern1 = { E8 F5 ?? ?? ?? ?? 8B 45 FC ?? ?? }
        $pattern2 = { 6A 00 8B 45 ?? ?? ?? ?? }

    condition:
        any of them
}