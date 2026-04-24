rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF D2 50 51 5E 5D C3 } // RtlAllocateHeap call + stack ops
        $pattern1 = { 48 00 48 00 48 00 75 3D } // DEC EAX/JNE evasion check
        $pattern2 = { E8 74 0A 00 00 8B 55 14 } // Function call + register manipulation

    condition:
        any of them
}