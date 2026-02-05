rule ConditionalJumpAndCallPattern
{
    meta:
        description = "Detects patterns involving test, jne, and call instructions"
    condition:
        50 E8 ?? ?? ?? ?? or
        85 C0 75 ?? or
        E8 ?? ?? ?? ?? 85 C0
}