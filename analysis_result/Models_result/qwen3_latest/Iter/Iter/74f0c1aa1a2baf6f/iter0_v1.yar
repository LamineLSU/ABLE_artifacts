rule EvasionDetection
{
    meta:
        description = "Detects potential evasion logic (anti-debugging, sandbox detection, etc.) through string comparisons and conditional jumps."
        cape_options = "bp0=$cmp_quotes+0,action0=skip,bp1=$cmp_space+0,action1=skip,bp2=$loop_quotes+0,action2=skip,count=0"

    strings:
        // Pattern 1: Initial string comparison (e.g., checking for quotes)
        $cmp_quotes = { 8A 01 3C 22 75 ?? }

        // Pattern 2: Conditional jump after checking for space (ASCII 20)
        $cmp_space = { 3C 20 7F ?? EB 07 }

        // Pattern 3: Loop checking for quotes with conditional jump
        $loop_quotes = { 83 C1 01 8A 11 3C 22 75 ?? }

    condition:
        any of them
}