rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rules for different evasive techniques"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B4068 ?? ?? ?? ?? ??:??.??.?? ?? 7510 }
        $pattern1 = { 83F801 ?? ?? ?? ?? 7510 ?? ?? ?? ?? ??.??.?? }
        $pattern2 = { FF7508 ?? ?? ?? ?? 4068 ?? ?? ?? ?? ??.??.?? }
}

# Pattern 0: Bypasses the AL check after pushing EAX
# Pattern matches when any displacement is followed by TEST and JNZ, allowing bypass
 cape_pattern $pattern0

# Pattern 1: Bypasses the AL test after comparing EBX with 0x01h
# The pattern skips over the conditional jump if not zero
 cape_pattern $pattern1

# Pattern 2: Bypasses the instruction after pushing EBP, allowing execution to proceed
 cape_pattern $pattern2