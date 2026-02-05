rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF D2 5E 5D C3 }  // CALL edx (RtlAllocateHeap) followed by RET
        $pattern1 = { 8D B0 74 0C 00 00 }   // LEA ESI with specific offset
        $pattern2 = { 31 82 4F 9B CB 55 }   // XOR dword ptr [edx+0x55CB9B4F] with EAX

    condition:
        any of them
}