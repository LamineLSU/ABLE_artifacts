rule Bypass_Sample_Evasion
{
    meta:
        description = "Evasion bypass detection rule (patterns include wildcards)"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 25 ?? ?? ?? 8B 47 03 }
        $pattern1 = { FF 75 ?? ?? FF ?A FF 4F ?? ?? 83 C4 ?? 6D 05 ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}