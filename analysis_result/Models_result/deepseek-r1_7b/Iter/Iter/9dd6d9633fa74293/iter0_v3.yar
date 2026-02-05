rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF7508 ?? ?? ?? ?? 59 }
        $pattern1 = { 55 ?? ?? ?? ?? 83 C4 }
        $pattern2 = { E8C8 ?? ?? ?? ?? 8B45 }

    condition:
        any of them
}