rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns targeting call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 E8 C8 FF FF FF 15 AC B0 41 00 }
        $pattern1 = { 6A ?? 8B FF FF 75 08 }
        $pattern2 = { 74 ?? ?? ?? ?? FF 15 AC B0 41 00 }

    condition:
        any_of($pattern0, $pattern1, $pattern2)
}