rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 4C 24 04 50 E8 ?? ?? ?? ?? EB ?? }
        $pattern1 = { B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? }
        $pattern2 = { 8B 4C 24 04 E8 ?? ?? ?? ?? }

    condition:
        any of them
}