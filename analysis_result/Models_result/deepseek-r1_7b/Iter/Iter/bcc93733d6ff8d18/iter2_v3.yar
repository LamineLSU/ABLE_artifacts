rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting multiple call patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 05 ?? ?? ?? ??
                     7412             # JE instruction
                     6A5B             # push 0000005Bh
                     5A               # pop edx
                     8BCE             # mov ecx, esi
                     E825050000       # call 000461F8h
                     0F84            # test eax, eax
                     ??               # displacement }
        $pattern1 = { E874FAFFFF     # call 00F861F8h
                     0A04             # push 00000104h
                     53               # push ebp
                     6A40             # push 00000040h
                     ??               # displacement }
        $pattern2 = { E857260000     # call 00FC61F8h
                     0C10             # push 00000110h
                     53               # push ebp
                     6840             # push 00FC1140h
                     ??               # displacement }

    condition:
        any of them
}