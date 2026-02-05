rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 70 44 41 00 85 C0 74 10 }  // IsWindowVisible test/je check
        $pattern1 = { FF 15 28 44 41 00 6A 00 FF 15 38 41 41 00 }  // Shell_NotifyIconA -> ExitProcess chain
        $pattern2 = { FF 15 8C 44 41 00 68 C0 5E 41 00 6A 00 }  // CreatePopupMenu setup

    condition:
        any of them
}