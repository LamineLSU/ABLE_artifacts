rule Bypass_Sample {
    meta:
        description: "Evasion bypass analysis"
        cape_options: "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? AE 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any() {
            instruction_at(0041E1AF) == 0x6A &&
            instruction_at(0041E1B0) == 0x8B &&
            instruction_at(0041E1B3) == '???' &&
            (instruction_at(0041E1BD) == 0x4D || instruction_at(0041E1BD) == 0x74) &&
            (instruction_at(0041E1BE) == 0x08 || instruction_at(0041E1BE) == 0x1F) &&
            instruction_at(0041E1BF) == '???' && 
            instruction_at(0041E1CA) == 0x6A &&
            instruction_at(0041E1CB) == 0x8B &&
            instruction_at(0041E1CC) == '???' &&
            (instruction_at(0041E1CD) == 0x4D || instruction_at(0041E1CD) == 0x74)
        }
}