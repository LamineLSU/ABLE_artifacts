rule Bypass_Sample {
    meta:
        description = "Evasion bypass rules based on sample traces"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? ?? }
        $pattern1 = { E8 C8 FF FF C0 FF 75 08 FF 15 AC B0 41 00 ?? ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }

    condition:
        any of them
}