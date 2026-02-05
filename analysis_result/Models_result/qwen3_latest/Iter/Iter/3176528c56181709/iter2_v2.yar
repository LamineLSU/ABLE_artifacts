rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "AI"
        date = "2023-10-15"
        license = "MIT"

    strings:
        $a = { FF D2 0D 0C 38 AB 22 } // RtlAllocateHeap call followed by OR
        $b = { 3D 99 EC 6D 6B }      // CMP instruction for conditional check
        $c = { E8 44 09 00 00 }      // Call to 0041A960

    condition:
        all of ($a, $b, $c)
}