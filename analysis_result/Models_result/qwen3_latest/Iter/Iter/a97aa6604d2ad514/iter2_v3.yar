rule EvasionCheck
{
    meta:
        description = "Identifies a code pattern associated with an evasion check or control flow."
        cape_options = "bp0=$call_unknown+0,action0=skip,bp1=$call_exit+0,action1=skip,bp2=$call_freeheap+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-15"

    strings:
        // Pattern 1: Call to an unknown function (0041F143h) followed by add esp
        $call_unknown = { E8 ?? ?? ?? ?? 83 C4 04 }

        // Pattern 2: Push edx followed by call eax (ExitProcess)
        $call_exit = { 52 FF D0 }

        // Pattern 3: Call to RtlFreeHeap
        $call_freeheap = { FF D2 }

    condition:
        all of them
}