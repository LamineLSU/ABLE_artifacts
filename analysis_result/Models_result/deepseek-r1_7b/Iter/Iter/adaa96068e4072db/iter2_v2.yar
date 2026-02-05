rule Bypass_Evasion_Tactic_V3 {
    meta:
        description: "Detects bypassed calls and conditional jumps in a malware's execution trace."
        cape_options: "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 ?? 8A ?? ?? ?? } // Around the E8 instruction
        $pattern1 = { FF ?? FD ?? F0 ?? FA } // Mid trace instructions
        $pattern2 = { F8 ?? F9 ?? FB ?? FC } // Another bypass attempt

    condition:
        any of them
}