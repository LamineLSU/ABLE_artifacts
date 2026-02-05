rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns targeting ExitProcess calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 E8 C8 FF FF FF FF 75 08 FF 75 08 ?? ?? }
        $pattern1 = { 6A 5B 8B 40 ?? ?? ?? ?? 03 C9 ?? ?? }
        $pattern2 = { 8B 45 55 E0 C9 BE ?? ?? ?? ?? ?? 5D 15 ?? }

    condition:
        any of them
}