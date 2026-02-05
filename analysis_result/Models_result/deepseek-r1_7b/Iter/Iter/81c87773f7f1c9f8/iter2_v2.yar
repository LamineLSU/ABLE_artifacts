rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { E8 ?? B5 D9 74 ?? ?? ?? ?? FF C0 }
        $pattern2 = { E8 DE 10 ?? ?? ?? ?? FF CE 75 C0 }

    condition:
        any of them
}