rule Pattern0
{
    meta:
        description = "RtlAllocateHeap allocation check (sandbox/VM detection)"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Malware Analyst"
        date = "2025-03-15"

    strings:
        $a = { 68 01 00 00 00 }  // PUSH 0x00000001
        $b = { 68 02 00 00 00 }  // PUSH 0x00000002
        $c = { 68 03 00 00 00 }  // PUSH 0x00000003
        $d = { E8 00 00 00 00 }  // CALL RtlAllocateHeap (offset varies)

    condition:
        all of ($a, $b, $c, $d)
}