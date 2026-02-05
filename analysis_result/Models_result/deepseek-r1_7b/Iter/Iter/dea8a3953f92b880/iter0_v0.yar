rule Bypass_Sample {
    meta: description = "Evasion bypass detection"
    cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B ?? 5A 8B CE E8 25 05 00 00 03 C3 BA 04 01 00 00 53 53 68 40 11 11 00 }
        $pattern1 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF 59 FF 75 08 FF 15 AC B0 41 00 ?? ?? ?? ?? 85 C0 5A }
        $pattern2 = { 6A 5B 5A 8B CE E8 25 05 00 00 03 C3 BA 04 01 00 00 53 53 68 40 11 1F 00 8B EC FF 75 08 FF 15 AC B0 41 00 ?? ?? ?? ?? }
}

    condition: any_of($pattern0, $pattern1, $pattern2)
}