rule Bypass_Sample
{
    meta:
        description = "Bypasses evasion checks by skipping critical API calls"
        cape_options = "bp0=$call_alloc+0,action0=skip,bp1=$call_free+0,action1=skip,bp2=$call_check+0,action2=skip,count=0"
        author = "ThreatIntel"
        date = "2023-10-05"
    strings:
        $call_alloc = { E8 ?? ?? ?? ?? } // CALL to RtlAllocateHeap
        $call_free = { E8 ?? ?? ?? ?? } // CALL to RtlFreeHeap
        $call_check = { E8 ?? ?? ?? ?? } // CALL to internal check routine
    condition:
        all of them
}