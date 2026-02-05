rule Bypass_Sample {
    meta:
        description = "Evasion bypass by bypassing exit checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FF FF FF FF FF 5F 5E }
        $pattern1 = { 74 12 0F 84 FF CE E8 ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? }

    condition:
        any of them
}