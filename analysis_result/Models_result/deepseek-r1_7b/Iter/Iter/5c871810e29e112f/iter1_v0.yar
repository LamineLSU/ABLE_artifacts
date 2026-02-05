rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting memory accesses and call evasions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 6A ?? }
        $pattern2 = { FF 75 08 ?? FF C8 ?? ?? CE 13 }

    condition:
        any of them
}