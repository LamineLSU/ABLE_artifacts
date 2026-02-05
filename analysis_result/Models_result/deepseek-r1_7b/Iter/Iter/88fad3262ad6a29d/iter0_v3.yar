rule Bypass_Sample {
    meta: description = "Evasion bypass patterns targeting multiple check points",
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 85 C0 0F 84 ?? ?? ?? ?? 8B 35 AC F1 47 00 AE EA EC AD BA BA }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? ?? ?? ?? 85 C0 AE BA EA EC FC EF CA }
        $pattern2 = { 74 68 E7 00 03 E7 ?? ?? ?? ?? 85 C0 ?? AE AD EA BA ED EC }

    condition:
        any of them
}