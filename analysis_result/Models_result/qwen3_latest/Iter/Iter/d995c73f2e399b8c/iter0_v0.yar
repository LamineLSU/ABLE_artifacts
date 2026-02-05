rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 C4 ?? 52 FF D0 }  // ExitProcess call with stack adjustment
        $pattern1 = { 8B 55 ?? FF D2 }    // RtlAllocateHeap call with edx source
        $pattern2 = { 31 82 ?? ?? ?? ?? } // XOR obfuscation with memory address

    condition:
        all of them
}