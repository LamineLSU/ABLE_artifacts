rule Bypass_Sample
{
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? }
        $pattern1 = { FF 75 F8 ?? ?? ?? ?? }
        $pattern2 = { 8B 45 ?? ?? ?? ?? }

    condition:
        any of them
}