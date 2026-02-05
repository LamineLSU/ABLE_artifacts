rule Malware_Bypass
{
    meta:
        description = "Detects evasion patterns and exit calls in a malicious sample"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "AI Assistant"
        date = "2023-10-15"

    strings:
        $pattern0 = { 66 83 F8 01 75 20 } // cmp ax, 0x01h + jne evasion check
        $pattern1 = { FF 15 80 51 A1 03 } // call to Sleep (imported function)
        $pattern2 = { FF 15 34 51 A1 03 } // call to ExitProcess (imported function)

    condition:
        any of them
}