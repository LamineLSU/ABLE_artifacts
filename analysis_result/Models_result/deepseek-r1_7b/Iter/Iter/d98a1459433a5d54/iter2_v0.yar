rule BypassPatches {
    meta:
        description = "Evasion bypass patterns targeting specific addresses during exit process"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 33 FD FF FF 6A ?? 8B CE }
        $pattern1 = { 85 C0 0F 84 33 FD FF FF E8 ?? ?? CE }
        $pattern2 = { 85 C0 0F 84 33 FD FF FF ?? 5B ?? }

    condition:
        any of them
}