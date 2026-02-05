rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 66 81 3C 24 E4 07 ?? ?? ?? ?? }
        $pattern1 = { 81 FB 01 00 00 80 ?? ?? ?? ?? }
        $pattern2 = { 8B C3 83 C4 10 ?? ?? ?? ?? }

    condition:
        any of them
}