rule EvasionCheck
{
    meta:
        author = "CyberDefense"
        cape_options = "bp0=$cmp_jne+0,action0=skip,bp1=$get_currentprocess+0,action1=skip,bp2=$virtualalloc+0,action2=skip,count=0"
        description = "Detects evasion logic via conditional check and API calls"
        date = "2023-10-10"
        confidence = 85

    strings:
        $cmp_jne = { 83 7D FC 00 75 08 } // Conditional check before exit
        $get_currentprocess = { FF 15 B4 7D 42 00 } // API call to GetCurrentProcess
        $virtualalloc = { FF 15 5C 7D 42 00 } // API call to VirtualAllocExNuma

    condition:
        all of (
            $cmp_jne,
            $get_currentprocess,
            $virtualalloc
        )
}