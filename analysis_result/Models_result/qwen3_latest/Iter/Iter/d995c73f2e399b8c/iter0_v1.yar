rule RtlHeapCall_Detection
{
    meta:
        description = "Detects calls to RtlAllocateHeap and RtlFreeHeap, commonly used in malware for heap management."
        cape_options = "bp0=$alloc_call+0,action0=skip,bp1=$free_call+0,action1=skip,bp2=$alloc_setup+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"
        hash = "md5:1234567890abcdef1234567890abcdef"
    
    strings:
        // Call to RtlAllocateHeap (with offset bytes)
        $alloc_call = { FF 15 ?? ?? ?? ?? }  // call dword ptr [eax+0x0]

        // Call to RtlFreeHeap
        $free_call = { FF 15 ?? ?? ?? ?? }  // call dword ptr [eax+0x0]

        // Contextual setup for heap allocation (common before a call)
        $alloc_setup = { 55 8B EC 53 56 57 83 EC 18 6A 01 6A 00 }

        // Contextual cleanup after a heap allocation (common after a call)
        $alloc_cleanup = { 5F 5E 5B C9 C2 08 00 }

        // Contextual setup for heap freeing (common before a call)
        $free_setup = { 55 8B EC 53 56 57 83 EC 18 }

        // Contextual cleanup after a heap free (common after a call)
        $free_cleanup = { 5F 5E 5B C9 C2 08 00 }

    condition:
        // Match either the call to RtlAllocateHeap or RtlFreeHeap
        (all of them) or
        (any of them)
}