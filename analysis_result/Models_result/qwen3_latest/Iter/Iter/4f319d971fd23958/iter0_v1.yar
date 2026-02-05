rule EvasionCheck
{
    meta:
        description = "Detects potential evasion techniques involving heap operations and control flow checks."
        cape_options = "bp0=$call_freeheap+0,action0=skip,bp1=$test_eax_jz+0,action1=skip,bp2=$call_0041ead7+0,action2=skip,count=0"

    strings:
        // Pattern 0: Call to RtlFreeHeap with surrounding pushes and pops
        $call_freeheap = { 50 51 FF D2 59 59 }

        // Pattern 1: Test EAX and conditional jump (jz)
        $test_eax_jz = { 85 C0 0F 84 ?? ?? ?? ?? }

        // Pattern 2: Call to 0041EAD7h with surrounding pushes and LEA
        $call_0041ead7 = { 51 8D B0 ?? ?? ?? ?? 56 50 E8 ?? ?? ?? ?? }

    condition:
        all of them
}