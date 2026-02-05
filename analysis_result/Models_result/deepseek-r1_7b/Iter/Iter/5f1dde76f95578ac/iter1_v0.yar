rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting conditional checks before exit process"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 33 FD FF FF 74 12 8B 4D FC } // EAX test, je if zero before call
        $pattern1 = { 5A 0F 84 33 FD FF FF 74 12 53 } // Push ebp+1h then conditional jmp
        $pattern2 = { 6A 5B 0F 84 33 FD FF FF 74 12 8B CE } // Push 0x5BH followed by call

    condition:
        any of them
}