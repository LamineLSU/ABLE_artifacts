rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting VM sandbox detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 FE ?? ?? ?? ?? 8B 45 ?? } // Skips TEST EAX + JZ without condition
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } // Skips PUSH + POP before JUMP
        $pattern2 = { FE 9F ?? ?? ?? ?? 7D F3 FC 4C 00 } // Skips conditional instructions before TEST
}

condition:
    any of them
}