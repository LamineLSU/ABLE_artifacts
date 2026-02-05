rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { ?? ?? 8B ?? ?? E8 ?? ?? }
        $pattern1 = { 6A ?? 59 FF 75 ?? }
        $pattern2 = { ?? ?? ?? 83 EC ?? 56 B9 }

    condition:
        any of them
}