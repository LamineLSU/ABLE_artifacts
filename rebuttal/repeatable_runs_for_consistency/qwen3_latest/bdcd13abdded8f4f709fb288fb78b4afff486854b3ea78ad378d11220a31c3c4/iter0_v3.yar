rule RtlAllocateHeapCall
{
    meta:
        description = "Call to RtlAllocateHeap, used in anti-virtualization checks"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 52 8B 06 E8 ?? ?? ?? ?? }
    condition:
        $a
}