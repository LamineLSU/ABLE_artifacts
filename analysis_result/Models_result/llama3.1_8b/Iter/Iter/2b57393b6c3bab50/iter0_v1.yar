rule Evasion_Bypass
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF ?? ?? ?? ?? E8 ?? FE FF }
        $pattern1 = { 8D ?? E8 ?? F0 ?? ?? }
        $pattern2 = { FF ?? ?? ?? ?? ?? }

    condition:
        any of them
}