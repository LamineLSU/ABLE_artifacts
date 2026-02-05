rule Bypass_Evasion {
    meta:
        description = "Bypasses multiple offset checks in a sandbox environment"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? FF 7E }   // Skips XOR and call
        $pattern1 = { 89 B5 53 8D 8C 56 50 8B 53 56 8D 8C 56 8D 84 8A FF 0F 7E } // Skips push and test/jump
        $pattern2 = { 89 B5 56 8D 8C 56 50 8B 53 56 8D 8C 56 8D 84 8A FF 1F 7E }   // Skips different push sequence
    condition:
        any of them
}