rule Bypass_Evasion {
    meta:
        description = "Evasion bypass patterns targeting ExitProcess calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC FF 75 08 E8 C8 FF FF FF 59 }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }
        $pattern2 = { FF 75 08 E8 C8 FF FF FF ?? }

    condition:
        any_of them
}