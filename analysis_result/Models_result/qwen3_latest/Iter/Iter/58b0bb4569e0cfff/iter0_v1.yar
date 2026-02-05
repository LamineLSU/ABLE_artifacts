rule Pattern1 {
    meta:
        description = "Potential call to RtlAllocateHeap (Windows API)"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 8B 88 14 0A 00 00 51 FF D2 5E 5D C3 }
    condition:
        $a
}