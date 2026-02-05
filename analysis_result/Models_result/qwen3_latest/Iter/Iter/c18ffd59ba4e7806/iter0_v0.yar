rule MaliciousHeapManipulation
{
    meta:
        description = "Detects a pattern of register pushes followed by a call to a function, indicative of malicious heap manipulation."
        cape_options = "bp0=$push_sequence+0,action0=skip,count=0"
        author = "Security Analyst"
        date = "2025-04-01"
    strings:
        $push_sequence = { 52 52 50 50 51 FF D2 }  // push edx, push edx, push eax, push eax, push ecx, call edx
    condition:
        $push_sequence
}