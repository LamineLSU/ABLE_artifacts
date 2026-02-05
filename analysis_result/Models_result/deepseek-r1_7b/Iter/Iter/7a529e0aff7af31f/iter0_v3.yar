rule EvasionBypass {
    meta:
        description = "Evasion bypass patterns targeting memory jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC 5A 8B FF C8 FF FF FF FF FF FF FF FF FF FF FF FF FF }
        $pattern1 = { E8 C8 FF FF FF 41 57 FF FF FF FF FF FF FF FF FF FF FF FF FF }
        $pattern2 = { FF 15 AC B0 41 00 41 63 FF FF FF FF FF FF FF FF FF FF FF FF }

    condition:
        any of them
}