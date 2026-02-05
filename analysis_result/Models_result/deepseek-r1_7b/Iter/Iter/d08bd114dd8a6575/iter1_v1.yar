rule Bypass_Sample_Evasion {
    meta:
        description = "Evasion bypass rule - multiple patterns to avoid stack/addresses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 C8 ?? 3C E8 ?? }
        $pattern1 = { 5E ?? 2A 1F 8B 45 56 ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? }

    condition:
        any of them
}