rule EvasionBypass_Patterns {
    meta:
        description = "Maze Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 FF 75 08 }
        $pattern1 = { FF 15 2C A1 FF D3 C9 ?? ?? ?? }
        $pattern2 = { 6A 5B 8B CE FF 75 08 }

    condition:
        any of them
}