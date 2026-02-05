rule Corrected_Evasion_Patterns
{
    meta:
        description = "Detects evasion patterns involving stack manipulation and exit function calls"
    condition:
        all of them
        (
            // Pattern 0: Stack push followed by CRT exit call
            (FF7508 E8 ?? ?? ?? ??)
        )
        and
        (
            // Pattern 1: Stack push followed by ExitProcess call
            (FF7508 FF15 ?? ?? ?? ??)
        )
        and
        (
            // Pattern 2: Stack setup (push ebp, mov ebp, push ebp+08h)
            (55 8BEC FF7508)
        )
}