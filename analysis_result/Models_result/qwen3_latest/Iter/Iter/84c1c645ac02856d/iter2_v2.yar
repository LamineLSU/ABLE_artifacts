rule bypass_exit_point
{
    meta:
        description = "Detects memory patterns leading to an exit point with potential evasion bypass"
        cape_options = "bp0=$call_add+0,action0=skip,bp1=$lea_offset+0,action1=skip,bp2=$add_push+0,action2=skip,count=0"
        author = "Security Analyst"

    strings:
        // Pattern 1: Call to 0x41EB77 followed by add operation
        $call_add = { E8 ?? ?? ?? ?? 00 51 8D }

        // Pattern 2: LEA instruction with offset 0x00000CA0h
        $lea_offset = { 8D B0 ?? ?? ?? ?? }

        // Pattern 3: Add operation with displacement and surrounding pushes
        $add_push = { 51 00 51 8D 56 E8 ?? ?? ?? ?? }

    condition:
        all of them
}