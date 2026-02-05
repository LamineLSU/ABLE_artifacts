rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting memory addresses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 C4 }
        $pattern1 = { FF15887C4200 8B ?F ?F ?F ?F 83 C4 ?F ?F ?F ?F }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}