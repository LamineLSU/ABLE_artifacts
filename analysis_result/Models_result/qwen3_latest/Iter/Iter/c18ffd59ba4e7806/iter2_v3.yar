rule SampleDetection
{
    meta:
        description = "Detects sandboxed execution via API calls, control flow checks, and memory addressing patterns."
        cape_options = "bp0=$api_call+0,action0=skip,bp1=$conditional_jump+0,action1=skip,bp2=$memory_addressing+0,action2=skip,count=0"
    strings:
        $api_call = { 52 52 8B 16 50 50 51 51 FF D2 } // Pushes, movs, and call to RtlAllocateHeap
        $conditional_jump = { 5E 5E 5D 5D C3 75 CF } // Pops, ret, and jne for control flow checks
        $memory_addressing = { 8D B0 74 0C 00 00 } // lea instruction with hardcoded offset
    condition:
        all of them
}