rule ExampleRule {
    meta:
        description = "Example rule with three well-formed patterns"
    strings:
        $pattern0 = { FF 75 08 E8 ?? ?? ?? ?? }  // Push ebp, call (4 bytes + 4 bytes offset)
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }  // Call, add, cmp, jne
        $pattern2 = { E8 ?? ?? ?? ?? 59 FF 75 08 }  // Call, pop ecx, push ebp
    condition:
        all of them
}