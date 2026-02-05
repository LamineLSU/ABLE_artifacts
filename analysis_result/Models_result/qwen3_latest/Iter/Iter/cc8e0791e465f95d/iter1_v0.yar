rule Pattern0
{
    meta:
        description = "Call to NtWriteVirtualMemory followed by a jmp"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,count=0"
    strings:
        $a = { FF D2 ?? ?? ?? ?? ?? } // call edx
        $b = { EB 9E ?? ?? ?? ?? ?? } // jmp 0x9E
    condition:
        $a and $b
}