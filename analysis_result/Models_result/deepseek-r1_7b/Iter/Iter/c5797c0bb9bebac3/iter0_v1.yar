rule Bypass_Sample {
    meta:
        description = "Evasion bypass detected via specific instruction sequences."
        cape_options = "bp0=0040E7F3;action0=skip;bp1=0040E7F6;action1=skip;bp2=0040E7FF;action2=skip"

    strings:
        $pattern0 = { FF 75 08 E8 C8 FF FF } // Represents push dword ptr [ebp+08h] followed by call
        $pattern1 = { 0F C8 E8 FF 75 }       // Different instruction sequence
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } // Example with wildcards

    condition:
        any() {
            action0=skip,
            action1=skip,
            action2=skip
        }
}