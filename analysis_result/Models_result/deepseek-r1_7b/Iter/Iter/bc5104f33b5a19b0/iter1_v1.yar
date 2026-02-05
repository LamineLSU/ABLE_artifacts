rule Bypass_Sample {
    meta:
        description = "Evasion bypass targeting exit decision steps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 E8 45 FC 68 68 42 FB 74 D0 8D 84 24 18 5F }
        $pattern1 = { FF 15 A0 30 FB 00 83 C4 ?? ?? ?? ?? ?? ?? ?? ?? FF 15 B8 30 FB 00 }
        $pattern2 = { E8 4F 00 00 00 6A ?? 5A 74 ?? ?? ?? ?? FF 75 08 30 FB 00 }

    condition:
        any of them
}