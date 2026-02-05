rule Bypass_Evasion_Behavior {
    meta:
        description = "Evasion bypass detection rules"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of the target locations are matched
        // Check for each pattern matching specific instructions in the trace
        if (match 0x55, 0x??, 0xEC) {
            return true;
        }
        if (match E8, ??, ??, ??, ??, 0x8B, 0x41, 0xXX, 0x55, 0xEC) {
            return true;
        }
        if (match 6A, ??, 5A, 8B, CE, E8, ??, ??, ??, ??, 85, C0) {
            return true;
        }
}