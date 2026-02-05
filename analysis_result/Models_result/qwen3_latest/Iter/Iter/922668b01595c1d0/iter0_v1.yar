rule Evasion_Logic {
    meta:
        description = "Detects evasion logic that leads to termination"
    condition:
        (all of them)
        (E8 ?? ?? ?? ?? 83 F8 01 74 20) or
        (0F B6 C0 85 C0 75 10) or
        (E8 ?? ?? ?? ?? 83 F8 01)
}