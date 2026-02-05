rule Bypass_Sample_Evasion
{
    meta:
        description = "Evasion bypass using specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? }
        $pattern1 = { ?? ?? FF D0 }
        $pattern2 = { 7A ?? 75 7D ?? }

    condition:
        any of them
}