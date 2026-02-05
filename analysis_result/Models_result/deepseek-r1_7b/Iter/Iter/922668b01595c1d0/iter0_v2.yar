rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting call evasions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 5C ?? ?? ?? ?? 39 F7 4F ?? ?? ?? ?? }
        $pattern1 = { E1 DF 02 ?? ?? ?? ?? 8A FC ?? ?? ?? ?? }
        $pattern2 = { E9 D8 40 ?? ?? ?? ?? 6A ?? 5A 8B CE E8 }

    condition:
        any of them
}