rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting sandbox/VM evasion"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? 45 C9 74 ?? }
        $pattern1 = { 74 ?? 0F ?C ?? }
        $pattern2 = { 6A ?? 5A ??
                     8B ?? 83 ?? 
                     53 ?? 0D 
                     51 ?? ?? }

    condition:
        any of them
}