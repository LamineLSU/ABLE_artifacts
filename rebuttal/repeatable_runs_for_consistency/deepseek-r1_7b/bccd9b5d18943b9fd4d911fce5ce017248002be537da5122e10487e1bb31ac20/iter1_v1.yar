rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting 3 different patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85C0 7412 ?? ?? ?? ?? E825 0500 }
        $pattern1 = { 8BEC 5A 8BCE E8C8 ?? ?? ?? ?? FF C1 ?? }
        $pattern2 = { 6A5B ?? 5B 8BE5 8D43 ?? ?? ?? ?? E874 ?? }

    condition:
        any of them
}