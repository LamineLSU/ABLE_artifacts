rule Pattern0
{
    meta:
        description = "Register push and call sequence, possibly involving RtlAllocateHeap"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 52 8B 16 50 51 FF D2 5E 5D C3 }
    condition:
        $a
}