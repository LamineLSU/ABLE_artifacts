rule SampleRule
{
    meta:
        description = "Detects a specific pattern in the given code"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 55 E8 44 09 00 00 } // push ebp, call to RtlAllocateHeap
        $b = { 56 E5 08 E1 7D 8B 54 24 0C } // push esi, in, loope, mov
        $c = { E1 7D 19 0A 0A 60 50 } // loope, sbb, or
    condition:
        all of them
}