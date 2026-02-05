rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection using predictable register manipulation and jump patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF F8 4B 5A 8B CE E8 ?? ?? ?? ?? 8B 45 ?? ?? ?? }  // Skip initial setup
        $pattern1 = { 6A 5B 5A 8B CE E8 F0 F7 FF F9 AE 5E ?? ?? ?? ?? 8B EC ?? ?? }  // Jump bypass after conditional check
        $pattern2 = { 03 C3 8D 41 8B 45 5A 8B CE E8 BF FF F0 F7 FF F9 AE 5E ?? ?? }   // Memory access bypass
    condition:
        any_of_them
}