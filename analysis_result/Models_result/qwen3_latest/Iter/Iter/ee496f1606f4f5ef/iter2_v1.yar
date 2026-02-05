rule EvasionCheck
{
    meta:
        description = "Detects evasion logic via conditional check and exit call"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        confidence = 85

    strings:
        $a = { 83 7D FC 00 75 08 } // cmp [ebp-04h] == 0 + jne
        $b = { FF 15 88 7C 42 00 } // ExitProcess call
        $c = { FF 15 5C 7D 42 00 } // VirtualAllocExNuma call

    condition:
        all of them
}