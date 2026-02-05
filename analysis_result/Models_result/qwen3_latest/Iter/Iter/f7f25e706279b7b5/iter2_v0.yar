rule MemoryPatternIdentification
{
    meta:
        description = "Identifies known memory patterns including RtlAllocateHeap, LEA instruction, and call to 0x0041EAE7"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-15"

    strings:
        $pattern1 = { 8B 16 50 51 FF D2 }
        $pattern2 = { 8D B0 98 0C 00 00 }
        $pattern3 = { 8B 8D 08 01 00 00 E8 ?? ?? ?? ?? }

    condition:
        all of them
}